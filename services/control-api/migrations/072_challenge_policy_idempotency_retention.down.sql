LOCK TABLE challenge_policy_write_requests IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM challenge_policy_write_requests WHERE completed_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 072 contains completed idempotency retention facts';
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION protect_challenge_policy_write_request_053()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
        RAISE EXCEPTION 'challenge policy write facts cannot be removed' USING ERRCODE = 'P0001';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.completed_at IS NOT NULL OR NEW.outcome IS NOT NULL OR NEW.resource_id IS NOT NULL
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
    RETURN NEW;
END;
$$;

DROP INDEX challenge_policy_write_requests_retention_072;
ALTER TABLE challenge_policy_write_requests
    DROP CONSTRAINT challenge_policy_write_requests_retention_072,
    DROP COLUMN retention_expires_at;
