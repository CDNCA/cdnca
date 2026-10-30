-- 579（fix-cacheflow2 占位 587，merge-p22 按集成头连号改为 579，前驱钉 578_certificate_binding_reservations）。
-- 统一后台任务原生支持生产者逐项取消（CACHE-ADD-07 第三层）：缓存节点因取消而停下的目标，
-- 现在以 cancelled 结果写进统一任务（原先被记成 failed，任务中心显示失败 1/取消 0、到上限进 DLQ）。
-- 规则与缓存模块 rollup 一致：全部取消 = cancelled（无 cancel 命令，cancel_requested_at 为空）；
-- 成功/失败与取消混合 = partial_failed（有失败用 item_failed，否则 cancelled，无可重试项、不进 DLQ）。
-- 取消命令仍走原路径（sequence 0、无结果行、cancel_requested_at 非空）；重试只重排失败项，取消项保持终态。
LOCK TABLE schema_migrations,
    background_jobs,
    background_job_items,
    background_job_attempts,
    background_job_results,
    background_job_command_receipts
IN ACCESS EXCLUSIVE MODE;

DO $migration_579_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 578 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 578 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=578 AND
        migration_id='578_certificate_binding_reservations' AND
        checksum_sha256='139667f70fca4f1e4882ceab9e51f38ff351c044d093705d322f103175528600' AND
        down_checksum_sha256='72afa08de44c386b4d6de89274cbccaf3113c0e78afa48c40daa23fc2012fc05' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) THEN
        RAISE EXCEPTION 'migration 579 requires the exact verified 578 release head' USING ERRCODE='P5790';
    END IF;
END;
$migration_579_up$;

ALTER TABLE background_job_results
    DROP CONSTRAINT background_job_results_state_check,
    DROP CONSTRAINT background_job_results_check,
    ADD CONSTRAINT background_job_results_state_check CHECK (state IN ('succeeded','failed','cancelled')),
    ADD CONSTRAINT background_job_results_check CHECK (
        (state = 'failed' AND error_code IS NOT NULL) OR
        (state = 'succeeded' AND error_code IS NULL) OR
        (state = 'cancelled' AND error_code = 'cancelled' AND source = 'worker')
    );

ALTER TABLE background_job_command_receipts
    DROP CONSTRAINT background_job_command_receipts_result_check_104,
    ADD CONSTRAINT background_job_command_receipts_result_check_104 CHECK (
        (operation='cancel' AND result_state='cancelled' AND
         result_completed_count=result_total_count AND result_failure_code='cancelled' AND
         result_completed_at IS NOT NULL) OR
        (operation IN ('retry','replay') AND result_state='queued' AND result_attempt > 0 AND
         result_completed_count=result_succeeded_count+result_cancelled_count AND result_failed_count=0 AND
         result_failure_code IS NULL AND result_completed_at IS NULL)
    );

CREATE OR REPLACE FUNCTION protect_background_job_item()
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
    -- 579: sequence 0 = cancelled by a cancel command (no result row);
    -- sequence > 0 = the producer reported it stopped the item (worker result row).
    IF NEW.state = 'cancelled' AND NEW.sequence = 0 THEN
        IF parent.state <> 'cancelled' OR parent.attempt <> NEW.attempt OR
           parent.cancel_requested_at IS DISTINCT FROM NEW.completed_at OR
           NEW.sequence <> 0 OR NEW.error_code <> 'cancelled' THEN
            RAISE EXCEPTION 'cancelled item does not match parent cancellation';
        END IF;
        RETURN NEW;
    END IF;
    IF parent.state NOT IN ('running', 'succeeded', 'partial_failed', 'failed', 'cancelled') OR
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
    command_cancelled integer;
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
    SELECT count(*) FILTER (WHERE state='cancelled' AND sequence=0)::integer
    INTO command_cancelled
    FROM background_job_items WHERE tenant_id=checked_tenant_id AND job_id=checked_job_id;
    IF parent.state='queued' THEN
        IF failed<>0 OR command_cancelled<>0 OR completed<>succeeded+cancelled OR
           parent.last_error_code IS NOT NULL OR parent.cancel_requested_at IS NOT NULL THEN
            RAISE EXCEPTION 'queued background job projection is invalid';
        END IF;
    ELSIF parent.state='running' THEN
        IF command_cancelled<>0 OR parent.last_error_code IS NOT NULL OR parent.cancel_requested_at IS NOT NULL THEN
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
        IF completed<>parent.total_count OR succeeded=parent.total_count OR failed=parent.total_count OR
           cancelled=parent.total_count OR command_cancelled<>0 OR
           (failed>0 AND parent.last_error_code NOT IN ('item_failed','retries_exhausted')) OR
           (failed=0 AND parent.last_error_code IS DISTINCT FROM 'cancelled') OR
           parent.cancel_requested_at IS NOT NULL THEN
            RAISE EXCEPTION 'partially failed background job projection is invalid';
        END IF;
    ELSIF parent.state='cancelled' THEN
        IF completed<>parent.total_count OR cancelled=0 OR parent.last_error_code<>'cancelled' OR NOT (
               (parent.cancel_requested_at IS NOT NULL AND
                parent.cancel_requested_at IS NOT DISTINCT FROM parent.completed_at) OR
               (parent.cancel_requested_at IS NULL AND cancelled=parent.total_count AND command_cancelled=0)
           ) THEN
            RAISE EXCEPTION 'cancelled background job projection is invalid';
        END IF;
    END IF;
    IF EXISTS (
        SELECT 1 FROM background_job_items item
        WHERE item.tenant_id=checked_tenant_id AND item.job_id=checked_job_id AND
              (item.state IN ('succeeded','failed') OR (item.state='cancelled' AND item.sequence>0)) AND NOT EXISTS (
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
        IF running_attempts<>0 OR
           current_attempt.state NOT IN ('failed','partial_failed','lease_expired','deferred') OR
           (current_attempt.state='lease_expired' AND NOT (
                current_attempt.error_code IS NOT DISTINCT FROM 'lease_expired' AND
                current_attempt.completed_at IS NOT NULL AND parent.claimable_at>parent.updated_at
           )) OR
           (current_attempt.state='deferred' AND NOT (
                current_attempt.error_code IS NOT DISTINCT FROM 'provider_retry_after' AND
                current_attempt.completed_at IS NOT DISTINCT FROM parent.updated_at AND
                parent.claimable_at>parent.updated_at AND parent.attempt<parent.max_attempts AND EXISTS (
                    SELECT 1 FROM background_job_yield_facts_115 fact
                    WHERE fact.tenant_id=parent.tenant_id AND fact.job_id=parent.id
                      AND fact.attempt=parent.attempt AND fact.lease_id=current_attempt.lease_id
                      AND fact.worker_id=current_attempt.worker_id AND fact.yielded_at=parent.updated_at
                      AND fact.not_before=parent.claimable_at
                )
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
       (NEW.state='partial_failed' AND NEW.error_code NOT IN ('item_failed','cancelled')) OR
       (NEW.state='failed' AND NEW.error_code<>'all_items_failed') OR
       (NEW.state='cancelled' AND NEW.error_code<>'cancelled') OR
       (NEW.state='lease_expired' AND NEW.error_code<>'lease_expired') OR
       (NEW.state='deferred' AND NEW.error_code<>'provider_retry_after') THEN
        RAISE EXCEPTION 'background job attempt terminal error is invalid';
    END IF;
    IF NEW.state = 'deferred' THEN
        IF parent.state<>'queued' OR parent.claimable_at<=NEW.completed_at OR
           parent.lease_id IS NOT NULL OR parent.lease_owner IS NOT NULL OR parent.lease_expires_at IS NOT NULL OR
           NOT EXISTS (
               SELECT 1 FROM background_job_yield_facts_115 fact
               WHERE fact.tenant_id=NEW.tenant_id AND fact.job_id=NEW.job_id
                 AND fact.attempt=NEW.attempt AND fact.lease_id=NEW.lease_id
                 AND fact.worker_id=NEW.worker_id AND fact.yielded_at=NEW.completed_at
                 AND fact.not_before=parent.claimable_at AND fact.yield_xact_id=pg_current_xact_id()
           ) THEN
            RAISE EXCEPTION 'deferred attempt does not match voluntary yield';
        END IF;
    ELSIF NEW.state = 'lease_expired' THEN
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

CREATE OR REPLACE FUNCTION mark_background_job_command_mutation_094()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    command_operation text;
    replay_count integer;
BEGIN
    IF TG_OP='INSERT' THEN
        IF NEW.job_command_operation IS NOT NULL OR NEW.job_command_xact_id IS NOT NULL THEN
            RAISE EXCEPTION 'background job command markers are database managed'
                USING ERRCODE='P9402';
        END IF;
        RETURN NEW;
    END IF;
    IF ROW(NEW.job_command_operation,NEW.job_command_xact_id) IS DISTINCT FROM
       ROW(OLD.job_command_operation,OLD.job_command_xact_id) THEN
        RAISE EXCEPTION 'background job command markers are database managed'
            USING ERRCODE='P9402';
    END IF;

    -- 579: a producer that reports every item cancelled ends the job cancelled
    -- without a cancel command; only a command sets cancel_requested_at.
    IF OLD.state IN ('queued','running') AND NEW.state='cancelled' AND NEW.cancel_requested_at IS NOT NULL THEN
        IF dns_reconcile_background_job_cancel_094(OLD,NEW) THEN
            command_operation := 'dns_cancel';
        ELSE
            command_operation := 'cancel';
        END IF;
    ELSIF OLD.state IN ('failed','partial_failed') AND NEW.state='queued' THEN
        SELECT count(*) INTO replay_count
        FROM background_job_replay_facts fact
        WHERE fact.tenant_id=OLD.tenant_id AND fact.job_id=OLD.id
          AND fact.dead_letter_attempt=OLD.attempt
          AND fact.old_max_attempts=OLD.max_attempts
          AND fact.new_max_attempts=NEW.max_attempts
          AND fact.job_command_xact_id=pg_current_xact_id();
        IF replay_count > 1 THEN
            RAISE EXCEPTION 'background job replay has multiple transaction facts'
                USING ERRCODE='P9402';
        ELSIF replay_count=1 THEN
            command_operation := 'replay';
        ELSIF dns_reconcile_background_job_recovery_retry_089(OLD,NEW) AND EXISTS (
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
        IF OLD.job_command_xact_id=pg_current_xact_id() THEN
            RAISE EXCEPTION 'background job already has a command mutation in this transaction'
                USING ERRCODE='P9402';
        END IF;
        NEW.job_command_operation := command_operation;
        NEW.job_command_xact_id := pg_current_xact_id();
    END IF;
    RETURN NEW;
END;
$$;
