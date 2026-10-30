LOCK TABLE schema_migrations,rollouts,node_deployments,edge_command_outbox,edge_rollout_write_requests IN ACCESS EXCLUSIVE MODE;

DO $migration_172_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>172 OR
       (SELECT max(version) FROM schema_migrations)<>172 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=172 AND migration_id='172_edge_rollout_cohorts' AND
          checksum_sha256='3107d44d94e8a55de68dc14d12733e3d6bdac5e8fa9d9aa581f83a8faa9bfd0e' AND integrity_state='verified'
    ) THEN
        RAISE EXCEPTION 'migration 172 rollback requires the exact verified 172 head' USING ERRCODE='P1726';
    END IF;
    IF EXISTS (SELECT 1 FROM rollouts WHERE contract_version=2 OR strategy<>'all_at_once' OR canary_size<>0 OR batch_size<>0 OR
        failure_threshold<>0 OR released_cohort<>0 OR pause_reason IS NOT NULL OR started_at IS NOT NULL OR paused_at IS NOT NULL) OR
       EXISTS (SELECT 1 FROM node_deployments WHERE cohort<>0) OR EXISTS (SELECT 1 FROM edge_command_outbox WHERE status='held') OR
       EXISTS (SELECT 1 FROM edge_rollout_write_requests WHERE operation IN ('edge_rollout.start','edge_rollout.pause','edge_rollout.resume')) THEN
        RAISE EXCEPTION 'migration 172 rollback would discard rollout cohort facts' USING ERRCODE='P1727';
    END IF;
END;
$migration_172_down$;

DROP TRIGGER edge_command_outbox_state_172 ON edge_command_outbox;
DROP FUNCTION enforce_edge_outbox_state_172();
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

ALTER TABLE edge_rollout_write_requests DROP CONSTRAINT edge_rollout_write_requests_operation_172;
ALTER TABLE edge_rollout_write_requests ADD CONSTRAINT edge_rollout_write_requests_operation_check CHECK (
    operation IN ('edge_rollout.cancel','edge_rollout.retry')
);
ALTER TABLE edge_command_outbox DROP CONSTRAINT edge_command_outbox_status_172;
ALTER TABLE edge_command_outbox ADD CONSTRAINT edge_command_outbox_status_046 CHECK (
    status IN ('pending','publishing','published','failed','cancelled')
);
DROP TRIGGER rollouts_state_172 ON rollouts;
DROP FUNCTION enforce_rollout_state_172();
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

ALTER TABLE rollouts DROP CONSTRAINT rollouts_contract_version_172;
ALTER TABLE rollouts ADD CONSTRAINT rollouts_contract_version_046 CHECK (contract_version IN (0,1));
ALTER TABLE rollouts DROP CONSTRAINT rollouts_status_172;
ALTER TABLE rollouts ADD CONSTRAINT rollouts_status_check CHECK (
    status IN ('building','queued','paused','completed','failed','cancelled')
);
CREATE OR REPLACE FUNCTION protect_node_deployment_command()
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
ALTER TABLE node_deployments DROP CONSTRAINT node_deployments_cohort_172;
ALTER TABLE node_deployments DROP COLUMN cohort;
ALTER TABLE rollouts DROP CONSTRAINT rollouts_started_paused_172;
ALTER TABLE rollouts DROP CONSTRAINT rollouts_pause_reason_172;
ALTER TABLE rollouts DROP CONSTRAINT rollouts_cohort_sizes_172;
ALTER TABLE rollouts DROP CONSTRAINT rollouts_strategy_172;
ALTER TABLE rollouts DROP COLUMN paused_at, DROP COLUMN started_at, DROP COLUMN pause_reason,
    DROP COLUMN released_cohort, DROP COLUMN failure_threshold, DROP COLUMN batch_size,
    DROP COLUMN canary_size, DROP COLUMN strategy;
