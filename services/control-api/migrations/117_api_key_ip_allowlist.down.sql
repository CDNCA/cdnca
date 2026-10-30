CREATE OR REPLACE FUNCTION protect_api_key_lifecycle()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
        RAISE EXCEPTION 'API keys cannot be deleted or truncated';
    END IF;

    IF TG_OP = 'INSERT' THEN
        IF NEW.status = 'revoked' OR NEW.revision <> 1 OR
           NEW.updated_at IS DISTINCT FROM NEW.created_at OR NEW.last_used_at IS NOT NULL OR
           (NEW.status = 'pending_activation' AND NEW.pending_expires_at <= NEW.created_at) OR
           (NEW.status = 'active' AND NEW.activated_at IS DISTINCT FROM NEW.created_at) THEN
            RAISE EXCEPTION 'invalid API key creation facts';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.id IS DISTINCT FROM OLD.id OR
       NEW.key_id IS DISTINCT FROM OLD.key_id OR
       NEW.key_prefix IS DISTINCT FROM OLD.key_prefix OR
       NEW.scope_id IS DISTINCT FROM OLD.scope_id OR
       NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR
       NEW.user_id IS DISTINCT FROM OLD.user_id OR
       NEW.created_by_user_id IS DISTINCT FROM OLD.created_by_user_id OR
       NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'API key identity and creation facts are immutable';
    END IF;
    IF OLD.status = 'revoked' THEN
        RAISE EXCEPTION 'revoked API key is immutable';
    END IF;

    IF NEW.last_used_at IS DISTINCT FROM OLD.last_used_at THEN
        IF NEW.name IS DISTINCT FROM OLD.name OR
           NEW.scopes IS DISTINCT FROM OLD.scopes OR
           NEW.secret_digest IS DISTINCT FROM OLD.secret_digest OR
           NEW.status IS DISTINCT FROM OLD.status OR
           NEW.pending_expires_at IS DISTINCT FROM OLD.pending_expires_at OR
           NEW.expires_at IS DISTINCT FROM OLD.expires_at OR
           NEW.activated_at IS DISTINCT FROM OLD.activated_at OR
           NEW.revoked_at IS DISTINCT FROM OLD.revoked_at OR
           NEW.revoked_by_user_id IS DISTINCT FROM OLD.revoked_by_user_id OR
           NEW.revision IS DISTINCT FROM OLD.revision OR
           NEW.updated_at IS DISTINCT FROM OLD.updated_at OR
           NEW.status <> 'active' OR NEW.last_used_at IS NULL OR
           (OLD.last_used_at IS NOT NULL AND NEW.last_used_at <= OLD.last_used_at) OR
           NEW.activated_at IS NULL OR NEW.last_used_at < NEW.activated_at OR
           (NEW.expires_at IS NOT NULL AND
               (transaction_timestamp() >= NEW.expires_at OR NEW.last_used_at >= NEW.expires_at)) THEN
            RAISE EXCEPTION 'API key usage update must be isolated, active, unexpired, and strictly monotonic';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.revision <> OLD.revision + 1 OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'API key lifecycle revision and timestamps must advance monotonically';
    END IF;

    IF OLD.status = 'pending_activation' AND NEW.status = 'active' THEN
        IF OLD.secret_digest IS NOT NULL OR NEW.secret_digest IS NULL OR
           NEW.pending_expires_at IS NOT NULL OR
           NEW.name IS DISTINCT FROM OLD.name OR NEW.scopes IS DISTINCT FROM OLD.scopes OR
           NEW.expires_at IS DISTINCT FROM OLD.expires_at OR
           NEW.activated_at IS NULL OR NEW.activated_at IS DISTINCT FROM NEW.updated_at OR
           NEW.activated_at < OLD.updated_at OR NEW.activated_at >= OLD.pending_expires_at OR
           transaction_timestamp() >= OLD.pending_expires_at OR
           (NEW.expires_at IS NOT NULL AND NEW.activated_at >= NEW.expires_at) OR
           (NEW.expires_at IS NOT NULL AND transaction_timestamp() >= NEW.expires_at) OR
           NEW.revoked_at IS NOT NULL OR NEW.revoked_by_user_id IS NOT NULL THEN
            RAISE EXCEPTION 'invalid API key activation transition';
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.status = 'active' AND NEW.status = 'active' AND
       NEW.secret_digest IS NOT DISTINCT FROM OLD.secret_digest THEN
        IF (NEW.name IS NOT DISTINCT FROM OLD.name AND
            NEW.scopes IS NOT DISTINCT FROM OLD.scopes AND
            NEW.expires_at IS NOT DISTINCT FROM OLD.expires_at) OR
           NEW.pending_expires_at IS NOT NULL OR
           NEW.activated_at IS DISTINCT FROM OLD.activated_at OR
           NEW.revoked_at IS NOT NULL OR NEW.revoked_by_user_id IS NOT NULL OR
           (NEW.expires_at IS NOT NULL AND NEW.updated_at >= NEW.expires_at) THEN
            RAISE EXCEPTION 'invalid API key metadata update';
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.status = 'active' AND NEW.status = 'active' AND
       NEW.secret_digest IS DISTINCT FROM OLD.secret_digest THEN
        IF NEW.secret_digest IS NULL OR NEW.name IS DISTINCT FROM OLD.name OR
           NEW.scopes IS DISTINCT FROM OLD.scopes OR NEW.expires_at IS DISTINCT FROM OLD.expires_at OR
           NEW.pending_expires_at IS NOT NULL OR
           NEW.activated_at IS DISTINCT FROM OLD.activated_at OR
           NEW.revoked_at IS NOT NULL OR NEW.revoked_by_user_id IS NOT NULL OR
           (OLD.expires_at IS NOT NULL AND transaction_timestamp() >= OLD.expires_at) OR
           (NEW.expires_at IS NOT NULL AND NEW.updated_at >= NEW.expires_at) THEN
            RAISE EXCEPTION 'invalid API key rotation transition';
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.status IN ('pending_activation', 'active') AND NEW.status = 'revoked' THEN
        IF NEW.secret_digest IS DISTINCT FROM OLD.secret_digest OR
           NEW.name IS DISTINCT FROM OLD.name OR NEW.scopes IS DISTINCT FROM OLD.scopes OR
           NEW.expires_at IS DISTINCT FROM OLD.expires_at OR
           NEW.pending_expires_at IS NOT NULL OR
           NEW.activated_at IS DISTINCT FROM OLD.activated_at OR
           NEW.revoked_at IS NULL OR NEW.revoked_at IS DISTINCT FROM NEW.updated_at OR
           NEW.revoked_at < COALESCE(OLD.last_used_at, OLD.activated_at, OLD.updated_at) OR
           NEW.revoked_by_user_id IS NULL THEN
            RAISE EXCEPTION 'invalid API key revocation transition';
        END IF;
        RETURN NEW;
    END IF;

    RAISE EXCEPTION 'invalid API key lifecycle transition';
END;
$$;

ALTER TABLE api_keys
    DROP CONSTRAINT api_keys_ip_allowlist_valid,
    DROP COLUMN ip_allowlist;

DROP FUNCTION api_key_ip_allowlist_is_valid(text[]);
