CREATE TABLE account_recovery_dispatch_claims (
    reference uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    user_id uuid NOT NULL,
    challenge_id uuid NOT NULL UNIQUE REFERENCES account_recovery_challenges(id) ON DELETE RESTRICT,
    kek_key_id text NOT NULL CHECK (
        octet_length(kek_key_id) BETWEEN 1 AND 128 AND
        kek_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    wrapped_data_key bytea NOT NULL CHECK (octet_length(wrapped_data_key) = 60),
    sealed_token bytea NOT NULL CHECK (octet_length(sealed_token) = 71),
    aad_sha256 bytea NOT NULL CHECK (octet_length(aad_sha256) = 32),
    email_digest bytea CHECK (email_digest IS NULL OR octet_length(email_digest) = 32),
    phone_digest bytea CHECK (phone_digest IS NULL OR octet_length(phone_digest) = 32),
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL CHECK (expires_at > issued_at),
    FOREIGN KEY (scope_id, user_id) REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT
);

CREATE INDEX account_recovery_dispatch_claims_expiry_050
    ON account_recovery_dispatch_claims (expires_at);

CREATE FUNCTION validate_account_recovery_dispatch_claim_050()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM account_recovery_challenges challenge
        JOIN account_recovery_write_requests write_request
          ON write_request.id = challenge.issued_by_write_id
        WHERE challenge.id = NEW.challenge_id
          AND challenge.tenant_id = NEW.tenant_id
          AND challenge.scope_id = NEW.scope_id
          AND challenge.user_id = NEW.user_id
          AND challenge.issued_at = NEW.issued_at
          AND challenge.expires_at = NEW.expires_at
          AND challenge.consumed_at IS NULL
          AND challenge.revoked_at IS NULL
          AND write_request.operation = 'request'
          AND write_request.completed_at IS NULL
    ) THEN
        RAISE EXCEPTION 'invalid account recovery dispatch claim';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM notification_events event
        JOIN notification_outbox outbox
          ON outbox.scope_id = event.scope_id AND outbox.event_id = event.id
        WHERE event.scope_id = NEW.scope_id
          AND event.recipient_kind = 'anonymous'
          AND event.event_type = 'identity.account_recovery'
          AND event.delivery_policy = 'system_required'
          AND event.anonymous_dispatch_reference = NEW.reference
          AND event.source_event_id = NEW.reference::text
    ) THEN
        RAISE EXCEPTION 'account recovery dispatch claim requires notification outbox';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER account_recovery_dispatch_claims_validate_050
BEFORE INSERT ON account_recovery_dispatch_claims
FOR EACH ROW EXECUTE FUNCTION validate_account_recovery_dispatch_claim_050();

CREATE FUNCTION protect_account_recovery_dispatch_claim_050()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'account recovery dispatch claims are append-only';
END;
$$;

CREATE TRIGGER account_recovery_dispatch_claims_protected_050
BEFORE UPDATE OR DELETE ON account_recovery_dispatch_claims
FOR EACH ROW EXECUTE FUNCTION protect_account_recovery_dispatch_claim_050();

CREATE FUNCTION prevent_account_recovery_dispatch_truncate_050()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'account recovery dispatch claims cannot be truncated';
END;
$$;

CREATE TRIGGER account_recovery_dispatch_claims_no_truncate_050
BEFORE TRUNCATE ON account_recovery_dispatch_claims
FOR EACH STATEMENT EXECUTE FUNCTION prevent_account_recovery_dispatch_truncate_050();
