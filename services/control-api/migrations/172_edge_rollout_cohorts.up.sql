LOCK TABLE schema_migrations,rollouts,node_deployments,edge_command_outbox,edge_rollout_write_requests IN ACCESS EXCLUSIVE MODE;

DO $migration_172$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>171 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>171 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=171 AND migration_id='171_recharge_payment_approval' AND
              checksum_sha256='0acba33bda1accbd9a4ae03eaebcb6fbd495be78c8e5fcb84a7fa57abf561ab9' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 172 requires the exact verified 171 release head' USING ERRCODE='P1720';
    END IF;
END;
$migration_172$;

ALTER TABLE rollouts
    ADD COLUMN strategy text NOT NULL DEFAULT 'all_at_once',
    ADD COLUMN canary_size integer NOT NULL DEFAULT 0,
    ADD COLUMN batch_size integer NOT NULL DEFAULT 0,
    ADD COLUMN failure_threshold integer NOT NULL DEFAULT 0,
    ADD COLUMN released_cohort integer NOT NULL DEFAULT 0,
    ADD COLUMN pause_reason text,
    ADD COLUMN started_at timestamptz,
    ADD COLUMN paused_at timestamptz,
    ADD CONSTRAINT rollouts_strategy_172 CHECK (strategy IN ('all_at_once','canary')),
    ADD CONSTRAINT rollouts_cohort_sizes_172 CHECK (
        (strategy='all_at_once' AND canary_size=0 AND batch_size=0 AND failure_threshold=0 AND released_cohort=0) OR
        (strategy='canary' AND canary_size BETWEEN 1 AND 1000 AND batch_size BETWEEN 1 AND 1000 AND
         failure_threshold BETWEEN 1 AND 10000 AND released_cohort BETWEEN -1 AND 10000)
    ),
    ADD CONSTRAINT rollouts_pause_reason_172 CHECK (pause_reason IS NULL OR pause_reason IN ('operator','failure_threshold')),
    ADD CONSTRAINT rollouts_started_paused_172 CHECK (paused_at IS NULL OR started_at IS NOT NULL);

ALTER TABLE rollouts DROP CONSTRAINT rollouts_contract_version_046;
ALTER TABLE rollouts ADD CONSTRAINT rollouts_contract_version_172 CHECK (contract_version IN (0, 1, 2));
ALTER TABLE rollouts DROP CONSTRAINT rollouts_status_check;
ALTER TABLE rollouts ADD CONSTRAINT rollouts_status_172 CHECK (
    status IN ('building','queued','running','paused','completed','failed','cancelled')
);

ALTER TABLE node_deployments
    ADD COLUMN cohort integer NOT NULL DEFAULT 0,
    ADD CONSTRAINT node_deployments_cohort_172 CHECK (cohort BETWEEN 0 AND 10000);

ALTER TABLE edge_command_outbox DROP CONSTRAINT edge_command_outbox_status_046;
ALTER TABLE edge_command_outbox ADD CONSTRAINT edge_command_outbox_status_172 CHECK (
    status IN ('pending','publishing','published','failed','cancelled','held')
);

ALTER TABLE edge_rollout_write_requests DROP CONSTRAINT edge_rollout_write_requests_operation_check;
ALTER TABLE edge_rollout_write_requests ADD CONSTRAINT edge_rollout_write_requests_operation_172 CHECK (
    operation IN ('edge_rollout.start','edge_rollout.pause','edge_rollout.resume','edge_rollout.cancel','edge_rollout.retry')
);

DROP TRIGGER rollouts_state_046 ON rollouts;
DROP FUNCTION enforce_rollout_state_046();
CREATE FUNCTION enforce_rollout_state_172()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF ROW(NEW.id, NEW.configuration_scope_id, NEW.config_version_id, NEW.action,
           NEW.idempotency_key, NEW.request_digest, NEW.request_id, NEW.correlation_id,
           NEW.traceparent, NEW.task_id, NEW.activation_timeout_ms,
           NEW.observation_window_ms, NEW.required_consecutive_successes,
           NEW.deadline_at, NEW.created_at, NEW.max_attempts, NEW.contract_version,
           NEW.strategy, NEW.canary_size, NEW.batch_size, NEW.failure_threshold)
       IS DISTINCT FROM
       ROW(OLD.id, OLD.configuration_scope_id, OLD.config_version_id, OLD.action,
           OLD.idempotency_key, OLD.request_digest, OLD.request_id, OLD.correlation_id,
           OLD.traceparent, OLD.task_id, OLD.activation_timeout_ms,
           OLD.observation_window_ms, OLD.required_consecutive_successes,
           OLD.deadline_at, OLD.created_at, OLD.max_attempts, OLD.contract_version,
           OLD.strategy, OLD.canary_size, OLD.batch_size, OLD.failure_threshold) THEN
        RAISE EXCEPTION 'rollout identity is immutable' USING ERRCODE='P1721';
    END IF;
    IF NEW.updated_at < OLD.updated_at OR NEW.released_cohort < OLD.released_cohort THEN
        RAISE EXCEPTION 'rollout monotonic facts regressed' USING ERRCODE='P1722';
    END IF;
    IF OLD.contract_version < 2 THEN
        IF OLD.status='building' AND NEW.status='queued' AND NEW.revision=OLD.revision THEN RETURN NEW; END IF;
        IF OLD.status='queued' AND NEW.status IN ('queued','cancelled') AND NEW.revision=OLD.revision+1 THEN RETURN NEW; END IF;
        RAISE EXCEPTION 'invalid legacy rollout state transition' USING ERRCODE='P1723';
    END IF;
    IF OLD.status='building' AND NEW.status IN ('queued','running') AND NEW.revision=OLD.revision THEN RETURN NEW; END IF;
    IF OLD.status='queued' AND NEW.status IN ('running','cancelled') AND NEW.revision=OLD.revision+1 THEN RETURN NEW; END IF;
    IF OLD.status='running' AND NEW.status IN ('running','paused','completed','failed','cancelled') AND NEW.revision=OLD.revision+1 THEN RETURN NEW; END IF;
    IF OLD.status='paused' AND NEW.status IN ('running','completed','failed','cancelled') AND NEW.revision=OLD.revision+1 THEN RETURN NEW; END IF;
    RAISE EXCEPTION 'invalid rollout state transition' USING ERRCODE='P1724';
END;
$$;
CREATE TRIGGER rollouts_state_172 BEFORE UPDATE ON rollouts FOR EACH ROW EXECUTE FUNCTION enforce_rollout_state_172();

CREATE OR REPLACE FUNCTION protect_node_deployment_command()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF ROW(NEW.id, NEW.rollout_id, NEW.node_id, NEW.attempt, NEW.config_version_id,
           NEW.previous_config_version_id, NEW.action, NEW.cohort, NEW.command_event_id,
           NEW.command_bytes, NEW.command_sha256, NEW.deadline_at, NEW.created_at)
       IS DISTINCT FROM
       ROW(OLD.id, OLD.rollout_id, OLD.node_id, OLD.attempt, OLD.config_version_id,
           OLD.previous_config_version_id, OLD.action, OLD.cohort, OLD.command_event_id,
           OLD.command_bytes, OLD.command_sha256, OLD.deadline_at, OLD.created_at) THEN
        RAISE EXCEPTION 'node deployment command identity is immutable';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER edge_command_outbox_state_046 ON edge_command_outbox;
DROP FUNCTION enforce_edge_outbox_state_046();
CREATE FUNCTION enforce_edge_outbox_state_172()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.status=NEW.status THEN RETURN NEW; END IF;
    IF OLD.status IN ('pending','failed') AND NEW.status='publishing' THEN RETURN NEW; END IF;
    IF OLD.status='pending' AND NEW.status IN ('cancelled','held') THEN RETURN NEW; END IF;
    IF OLD.status='held' AND NEW.status IN ('pending','cancelled') THEN RETURN NEW; END IF;
    IF OLD.status='publishing' AND NEW.status IN ('published','failed') THEN RETURN NEW; END IF;
    RAISE EXCEPTION 'invalid edge outbox state transition' USING ERRCODE='P1725';
END;
$$;
CREATE TRIGGER edge_command_outbox_state_172 BEFORE UPDATE OF status ON edge_command_outbox
FOR EACH ROW EXECUTE FUNCTION enforce_edge_outbox_state_172();
