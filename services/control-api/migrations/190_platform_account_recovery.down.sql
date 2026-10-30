LOCK TABLE account_recovery_dispatch_claims, account_recovery_rate_windows,
    account_recovery_challenges, account_recovery_write_requests IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM account_recovery_write_requests WHERE tenant_id IS NULL) OR
       EXISTS (SELECT 1 FROM account_recovery_challenges WHERE tenant_id IS NULL) OR
       EXISTS (SELECT 1 FROM account_recovery_rate_windows WHERE tenant_id IS NULL) OR
       EXISTS (SELECT 1 FROM account_recovery_dispatch_claims WHERE tenant_id IS NULL) THEN
        RAISE EXCEPTION 'platform account recovery facts prevent rollback';
    END IF;
END;
$$;

ALTER TABLE account_recovery_write_requests ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE account_recovery_challenges ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE account_recovery_rate_windows ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE account_recovery_dispatch_claims ALTER COLUMN tenant_id SET NOT NULL;

CREATE OR REPLACE FUNCTION validate_account_recovery_scope()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM access_scopes scope
        JOIN tenants tenant ON tenant.id = scope.tenant_id
        WHERE scope.id = NEW.scope_id AND scope.kind = 'tenant'
          AND scope.tenant_id = NEW.tenant_id
    ) THEN
        RAISE EXCEPTION 'account recovery requires the matching tenant scope';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION validate_account_recovery_challenge_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM access_scopes scope
        JOIN tenants tenant ON tenant.id = scope.tenant_id
        WHERE scope.id = NEW.scope_id AND scope.kind = 'tenant'
          AND scope.tenant_id = NEW.tenant_id
    ) THEN
        RAISE EXCEPTION 'account recovery requires the matching tenant scope';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM users user_row
        JOIN memberships membership
          ON membership.user_id = user_row.id AND membership.scope_id = NEW.scope_id
        JOIN account_recovery_write_requests write_request
          ON write_request.id = NEW.issued_by_write_id
        WHERE user_row.id = NEW.user_id
          AND user_row.status = 'active' AND membership.status = 'active'
          AND user_row.revision = NEW.password_revision
          AND write_request.tenant_id = NEW.tenant_id
          AND write_request.scope_id = NEW.scope_id
          AND write_request.operation = 'request'
          AND write_request.completed_at IS NULL
          AND write_request.created_at = NEW.issued_at
    ) THEN
        RAISE EXCEPTION 'invalid account recovery challenge issuance';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION protect_account_recovery_challenge()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'account recovery facts are append-only';
    END IF;
    IF OLD.consumed_at IS NOT NULL OR OLD.revoked_at IS NOT NULL THEN
        RAISE EXCEPTION 'account recovery challenge transition is already terminal';
    END IF;
    IF NEW.id IS DISTINCT FROM OLD.id OR
       NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR
       NEW.scope_id IS DISTINCT FROM OLD.scope_id OR
       NEW.user_id IS DISTINCT FROM OLD.user_id OR
       NEW.token_digest IS DISTINCT FROM OLD.token_digest OR
       NEW.subject_digest IS DISTINCT FROM OLD.subject_digest OR
       NEW.password_revision IS DISTINCT FROM OLD.password_revision OR
       NEW.issued_by_write_id IS DISTINCT FROM OLD.issued_by_write_id OR
       NEW.issued_at IS DISTINCT FROM OLD.issued_at OR
       NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN
        RAISE EXCEPTION 'account recovery facts are append-only';
    END IF;

    IF NEW.consumed_at IS NOT NULL AND NEW.revoked_at IS NULL AND
       NEW.terminal_reason = 'consumed' AND NEW.completion_write_id IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1
            FROM account_recovery_write_requests write_request
            JOIN users user_row ON user_row.id = OLD.user_id
            WHERE write_request.id = NEW.completion_write_id
              AND write_request.tenant_id = OLD.tenant_id
              AND write_request.scope_id = OLD.scope_id
              AND write_request.operation = 'reset'
              AND write_request.completed_at IS NULL
              AND user_row.revision = OLD.password_revision + 1
              AND user_row.updated_at = NEW.consumed_at
              AND NOT EXISTS (
                  SELECT 1 FROM auth_sessions session
                  WHERE session.user_id = OLD.user_id AND session.revoked_at IS NULL
              )
              AND EXISTS (
                  SELECT 1 FROM audit_events event
                  WHERE event.scope_id = OLD.scope_id
                    AND event.action = 'identity.account_recovery.reset'
                    AND event.resource_type = 'account_recovery_challenge'
                    AND event.resource_id = OLD.id::text
                    AND event.request_id = write_request.request_id
                    AND event.result = 'success'
              )
        ) THEN
            RAISE EXCEPTION 'account recovery challenge transition is not authorized';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.consumed_at IS NULL AND NEW.revoked_at IS NOT NULL AND
       NEW.completion_write_id IS NULL AND NEW.terminal_reason = 'superseded' THEN
        IF NOT EXISTS (
            SELECT 1 FROM account_recovery_challenges replacement
            WHERE replacement.id <> OLD.id
              AND replacement.scope_id = OLD.scope_id
              AND replacement.user_id = OLD.user_id
              AND replacement.issued_at = NEW.revoked_at
              AND replacement.consumed_at IS NULL
              AND replacement.revoked_at IS NULL
        ) THEN
            RAISE EXCEPTION 'account recovery challenge transition is not authorized';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.consumed_at IS NULL AND NEW.revoked_at IS NOT NULL AND
       NEW.completion_write_id IS NULL AND NEW.terminal_reason = 'principal_changed' THEN
        IF EXISTS (
            SELECT 1 FROM users user_row
            JOIN memberships membership
              ON membership.user_id = user_row.id AND membership.scope_id = OLD.scope_id
            WHERE user_row.id = OLD.user_id AND user_row.status = 'active'
              AND membership.status = 'active'
              AND user_row.revision = OLD.password_revision
        ) THEN
            RAISE EXCEPTION 'account recovery challenge transition is not authorized';
        END IF;
        RETURN NEW;
    END IF;

    RAISE EXCEPTION 'account recovery challenge transition is not authorized';
END;
$$;

CREATE OR REPLACE FUNCTION validate_account_recovery_dispatch_claim_050()
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
