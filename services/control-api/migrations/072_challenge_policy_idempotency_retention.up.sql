ALTER TABLE challenge_policy_write_requests
    ADD COLUMN retention_expires_at timestamptz;

-- ALTER TABLE holds ACCESS EXCLUSIVE through the migration transaction. Replacing the
-- row guard inside that lock permits only this deterministic historical backfill.
DROP TRIGGER challenge_policy_write_requests_guard_053 ON challenge_policy_write_requests;

UPDATE challenge_policy_write_requests
SET retention_expires_at = completed_at + interval '168 hours'
WHERE completed_at IS NOT NULL;

ALTER TABLE challenge_policy_write_requests
    ADD CONSTRAINT challenge_policy_write_requests_retention_072 CHECK (
        (completed_at IS NULL AND retention_expires_at IS NULL) OR
        (completed_at IS NOT NULL AND isfinite(completed_at) AND
         isfinite(retention_expires_at) AND
         retention_expires_at = completed_at + interval '168 hours')
    );

CREATE INDEX challenge_policy_write_requests_retention_072
    ON challenge_policy_write_requests (retention_expires_at, id)
    WHERE completed_at IS NOT NULL;

CREATE OR REPLACE FUNCTION protect_challenge_policy_write_request_053()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'TRUNCATE' THEN
        RAISE EXCEPTION 'challenge policy write facts cannot be truncated' USING ERRCODE = 'P0001';
    END IF;
    IF TG_OP = 'DELETE' THEN
        IF OLD.completed_at IS NULL OR OLD.retention_expires_at IS NULL
           OR OLD.retention_expires_at > transaction_timestamp() THEN
            RAISE EXCEPTION 'challenge policy write retention has not expired' USING ERRCODE = 'P0001';
        END IF;
        RETURN OLD;
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.completed_at IS NOT NULL OR NEW.retention_expires_at IS NOT NULL
           OR NEW.outcome IS NOT NULL OR NEW.resource_id IS NOT NULL
           OR NEW.response_status IS NOT NULL OR NEW.response_body IS NOT NULL THEN
            RAISE EXCEPTION 'challenge policy write must start incomplete' USING ERRCODE = 'P0001';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.completed_at IS NOT NULL
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.actor_scope_id IS DISTINCT FROM OLD.actor_scope_id
       OR NEW.actor_user_id IS DISTINCT FROM OLD.actor_user_id
       OR NEW.target_scope_id IS DISTINCT FROM OLD.target_scope_id
       OR NEW.operation IS DISTINCT FROM OLD.operation
       OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key
       OR NEW.request_digest IS DISTINCT FROM OLD.request_digest
       OR NEW.request_id IS DISTINCT FROM OLD.request_id
       OR NEW.trace_id IS DISTINCT FROM OLD.trace_id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.completed_at IS NULL OR NEW.outcome IS NULL
       OR NEW.response_status IS NULL OR NEW.response_body IS NULL THEN
        RAISE EXCEPTION 'invalid challenge policy write completion' USING ERRCODE = 'P0001';
    END IF;
    IF NOT isfinite(NEW.completed_at) THEN
        RAISE EXCEPTION 'challenge policy completion time must be finite' USING ERRCODE = 'P0001';
    END IF;
    NEW.retention_expires_at := NEW.completed_at + interval '168 hours';
    IF NOT isfinite(NEW.retention_expires_at) THEN
        RAISE EXCEPTION 'challenge policy retention expiry must be finite' USING ERRCODE = 'P0001';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER challenge_policy_write_requests_guard_053
BEFORE INSERT OR UPDATE OR DELETE ON challenge_policy_write_requests
FOR EACH ROW EXECUTE FUNCTION protect_challenge_policy_write_request_053();
