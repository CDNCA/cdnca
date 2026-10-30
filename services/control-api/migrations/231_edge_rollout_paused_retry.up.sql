LOCK TABLE schema_migrations, rollouts, edge_rollout_write_requests IN ACCESS EXCLUSIVE MODE;

DO $migration_231$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 230 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 230 OR
       EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 230 AND migration_id = '230_security_policy_system_role_projection' AND
              checksum_sha256 = '5a754062f0248ba9f8138cb3240f58a921968dc1526e551a78d5fcfc8e009551' AND
              down_checksum_sha256 = '5a37942455d54cd6534b987eb5365e8eaddc21410797cfe0eb9bc6651bfad0e6' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR to_regprocedure('enforce_rollout_state_172()') IS NULL OR NOT EXISTS (
        SELECT 1 FROM pg_trigger trigger
        JOIN pg_proc procedure ON procedure.oid = trigger.tgfoid
        WHERE trigger.tgrelid = 'rollouts'::regclass AND trigger.tgname = 'rollouts_state_172' AND
              NOT trigger.tgisinternal AND procedure.proname = 'enforce_rollout_state_172'
       ) THEN
        RAISE EXCEPTION 'migration 231 requires the exact verified 230 release head and canonical rollout guard'
            USING ERRCODE = 'P2310';
    END IF;
END;
$migration_231$;

CREATE OR REPLACE FUNCTION enforce_rollout_state_172()
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
    IF OLD.status='paused' AND NEW.status='paused' AND
       NEW.pause_reason IS NOT DISTINCT FROM OLD.pause_reason AND
       NEW.started_at IS NOT DISTINCT FROM OLD.started_at AND NEW.paused_at IS NOT DISTINCT FROM OLD.paused_at AND
       NEW.released_cohort=OLD.released_cohort AND NEW.revision=OLD.revision+1 AND EXISTS (
        SELECT 1 FROM edge_rollout_write_requests request
        WHERE request.configuration_scope_id=NEW.configuration_scope_id AND request.rollout_id=NEW.id AND
              request.operation='edge_rollout.retry' AND request.expected_revision=OLD.revision AND
              request.created_at=NEW.updated_at AND request.completed_at IS NULL
       ) THEN RETURN NEW; END IF;
    IF OLD.status='paused' AND NEW.status IN ('running','completed','failed','cancelled') AND NEW.revision=OLD.revision+1 THEN RETURN NEW; END IF;
    RAISE EXCEPTION 'invalid rollout state transition' USING ERRCODE='P1724';
END;
$$;
