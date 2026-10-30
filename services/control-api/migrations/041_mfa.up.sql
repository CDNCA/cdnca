CREATE TABLE mfa_credentials (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL,
    scope_id uuid NOT NULL,
    method text NOT NULL CHECK (method = 'totp'),
    account_label text NOT NULL CHECK (
        account_label = btrim(account_label) AND char_length(account_label) BETWEEN 1 AND 254 AND
        account_label !~ '[[:cntrl:]]' AND
        position(U&'\2028' IN account_label) = 0 AND position(U&'\2029' IN account_label) = 0
    ),
    secret_key_id text NOT NULL CHECK (
        secret_key_id = btrim(secret_key_id) AND char_length(secret_key_id) BETWEEN 1 AND 128 AND
        secret_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$'
    ),
    envelope_algorithm text NOT NULL CHECK (envelope_algorithm = 'external-envelope-v1'),
    secret_ciphertext bytea NOT NULL CHECK (octet_length(secret_ciphertext) BETWEEN 17 AND 4096),
    secret_ciphertext_sha256 bytea NOT NULL CHECK (octet_length(secret_ciphertext_sha256) = 32),
    totp_algorithm text NOT NULL CHECK (totp_algorithm = 'sha1'),
    totp_digits smallint NOT NULL CHECK (totp_digits = 6),
    totp_period_seconds smallint NOT NULL CHECK (totp_period_seconds = 30),
    idempotency_key text NOT NULL CHECK (idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    request_id text NOT NULL CHECK (
        request_id = btrim(request_id) AND char_length(request_id) BETWEEN 1 AND 128 AND
        request_id !~ '[[:cntrl:]]'
    ),
    trace_id text NOT NULL CHECK (
        trace_id = btrim(trace_id) AND char_length(trace_id) BETWEEN 1 AND 128 AND
        trace_id !~ '[[:cntrl:]]'
    ),
    encrypted_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    challenge_expires_at timestamptz NOT NULL,
    FOREIGN KEY (scope_id, user_id) REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    UNIQUE (user_id, scope_id, idempotency_key),
    UNIQUE (id, user_id, scope_id),
    CHECK (encrypted_at = created_at),
    CHECK (challenge_expires_at > created_at AND challenge_expires_at <= created_at + interval '15 minutes')
);

CREATE INDEX mfa_credentials_principal_created_idx
    ON mfa_credentials (user_id, scope_id, created_at DESC, id DESC);

CREATE TABLE mfa_credential_events (
    id uuid PRIMARY KEY,
    credential_id uuid NOT NULL,
    user_id uuid NOT NULL,
    scope_id uuid NOT NULL,
    event_type text NOT NULL CHECK (event_type IN (
        'activated', 'totp_verified', 'recovery_verified', 'disabled', 'reset'
    )),
    totp_counter bigint CHECK (totp_counter IS NULL OR totp_counter >= 0),
    recovery_code_id uuid,
    idempotency_key text NOT NULL CHECK (idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    request_id text NOT NULL CHECK (
        request_id = btrim(request_id) AND char_length(request_id) BETWEEN 1 AND 128 AND
        request_id !~ '[[:cntrl:]]'
    ),
    trace_id text NOT NULL CHECK (
        trace_id = btrim(trace_id) AND char_length(trace_id) BETWEEN 1 AND 128 AND
        trace_id !~ '[[:cntrl:]]'
    ),
    occurred_at timestamptz NOT NULL,
    FOREIGN KEY (credential_id, user_id, scope_id)
        REFERENCES mfa_credentials(id, user_id, scope_id) ON DELETE RESTRICT,
    UNIQUE (credential_id, event_type, idempotency_key),
    CHECK (
        (event_type IN ('activated', 'totp_verified') AND totp_counter IS NOT NULL AND recovery_code_id IS NULL) OR
        (event_type = 'recovery_verified' AND totp_counter IS NULL AND recovery_code_id IS NOT NULL) OR
        (event_type IN ('disabled', 'reset') AND totp_counter IS NULL AND recovery_code_id IS NULL)
    )
);

CREATE UNIQUE INDEX mfa_credential_events_activation_idx
    ON mfa_credential_events (credential_id) WHERE event_type = 'activated';
CREATE UNIQUE INDEX mfa_credential_events_terminal_idx
    ON mfa_credential_events (credential_id) WHERE event_type IN ('disabled', 'reset');
CREATE UNIQUE INDEX mfa_credential_events_totp_counter_idx
    ON mfa_credential_events (credential_id, totp_counter) WHERE totp_counter IS NOT NULL;
CREATE UNIQUE INDEX mfa_credential_events_recovery_idx
    ON mfa_credential_events (recovery_code_id) WHERE recovery_code_id IS NOT NULL;

CREATE TABLE mfa_recovery_codes (
    id uuid PRIMARY KEY,
    credential_id uuid NOT NULL,
    user_id uuid NOT NULL,
    scope_id uuid NOT NULL,
    ordinal smallint NOT NULL CHECK (ordinal BETWEEN 1 AND 10),
    code_digest bytea NOT NULL CHECK (octet_length(code_digest) = 32),
    created_at timestamptz NOT NULL,
    FOREIGN KEY (credential_id, user_id, scope_id)
        REFERENCES mfa_credentials(id, user_id, scope_id) ON DELETE RESTRICT,
    UNIQUE (credential_id, ordinal),
    UNIQUE (credential_id, code_digest),
    UNIQUE (id, credential_id, user_id, scope_id)
);

ALTER TABLE mfa_credential_events
    ADD CONSTRAINT mfa_credential_events_recovery_code_fk
    FOREIGN KEY (recovery_code_id, credential_id, user_id, scope_id)
    REFERENCES mfa_recovery_codes(id, credential_id, user_id, scope_id) ON DELETE RESTRICT;

CREATE TABLE mfa_recovery_code_consumptions (
    id uuid PRIMARY KEY,
    recovery_code_id uuid NOT NULL UNIQUE,
    credential_id uuid NOT NULL,
    user_id uuid NOT NULL,
    scope_id uuid NOT NULL,
    request_id text NOT NULL CHECK (
        request_id = btrim(request_id) AND char_length(request_id) BETWEEN 1 AND 128 AND
        request_id !~ '[[:cntrl:]]'
    ),
    trace_id text NOT NULL CHECK (
        trace_id = btrim(trace_id) AND char_length(trace_id) BETWEEN 1 AND 128 AND
        trace_id !~ '[[:cntrl:]]'
    ),
    consumed_at timestamptz NOT NULL,
    FOREIGN KEY (recovery_code_id, credential_id, user_id, scope_id)
        REFERENCES mfa_recovery_codes(id, credential_id, user_id, scope_id) ON DELETE RESTRICT
);

CREATE TABLE mfa_step_up_proofs (
    id uuid PRIMARY KEY,
    token_digest bytea NOT NULL UNIQUE CHECK (octet_length(token_digest) = 32),
    actor_user_id uuid NOT NULL,
    actor_scope_id uuid NOT NULL,
    auth_session_id uuid NOT NULL REFERENCES auth_sessions(id) ON DELETE RESTRICT,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    credential_id uuid NOT NULL,
    authentication_event_id uuid NOT NULL UNIQUE REFERENCES mfa_credential_events(id) ON DELETE RESTRICT,
    authentication_method text NOT NULL CHECK (authentication_method IN ('totp', 'recovery_code')),
    permissions_digest bytea NOT NULL CHECK (octet_length(permissions_digest) = 32),
    audience text NOT NULL CHECK (
        audience = btrim(audience) AND char_length(audience) BETWEEN 1 AND 128 AND
        audience !~ '[[:cntrl:]]'
    ),
    action text NOT NULL CHECK (
        action = btrim(action) AND char_length(action) BETWEEN 1 AND 128 AND
        action !~ '[[:cntrl:]]'
    ),
    max_uses smallint NOT NULL CHECK (max_uses BETWEEN 1 AND 5),
    idempotency_key text NOT NULL CHECK (idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    request_id text NOT NULL CHECK (
        request_id = btrim(request_id) AND char_length(request_id) BETWEEN 1 AND 128 AND
        request_id !~ '[[:cntrl:]]'
    ),
    trace_id text NOT NULL CHECK (
        trace_id = btrim(trace_id) AND char_length(trace_id) BETWEEN 1 AND 128 AND
        trace_id !~ '[[:cntrl:]]'
    ),
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    FOREIGN KEY (actor_scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY (credential_id, actor_user_id, actor_scope_id)
        REFERENCES mfa_credentials(id, user_id, scope_id) ON DELETE RESTRICT,
    UNIQUE (actor_user_id, actor_scope_id, auth_session_id, idempotency_key),
    UNIQUE (id, actor_user_id, actor_scope_id, auth_session_id, tenant_id),
    CHECK (expires_at > issued_at AND expires_at <= issued_at + interval '5 minutes')
);

CREATE INDEX mfa_step_up_proofs_principal_expiry_idx
    ON mfa_step_up_proofs (actor_user_id, actor_scope_id, auth_session_id, expires_at);

CREATE TABLE mfa_step_up_uses (
    id uuid PRIMARY KEY,
    proof_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    actor_scope_id uuid NOT NULL,
    auth_session_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    use_ordinal smallint NOT NULL CHECK (use_ordinal BETWEEN 1 AND 5),
    request_id text NOT NULL CHECK (
        request_id = btrim(request_id) AND char_length(request_id) BETWEEN 1 AND 128 AND
        request_id !~ '[[:cntrl:]]'
    ),
    trace_id text NOT NULL CHECK (
        trace_id = btrim(trace_id) AND char_length(trace_id) BETWEEN 1 AND 128 AND
        trace_id !~ '[[:cntrl:]]'
    ),
    used_at timestamptz NOT NULL,
    FOREIGN KEY (proof_id, actor_user_id, actor_scope_id, auth_session_id, tenant_id)
        REFERENCES mfa_step_up_proofs(id, actor_user_id, actor_scope_id, auth_session_id, tenant_id)
        ON DELETE RESTRICT,
    UNIQUE (proof_id, use_ordinal),
    UNIQUE (proof_id, request_id)
);

CREATE FUNCTION validate_mfa_credential_event()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    challenge_expires timestamptz;
    principal_active boolean;
    activated boolean;
    terminal boolean;
    strong_auth boolean;
BEGIN
    SELECT credential.challenge_expires_at,
           users.status = 'active' AND membership.status = 'active',
           EXISTS (SELECT 1 FROM mfa_credential_events event
                   WHERE event.credential_id = NEW.credential_id AND event.event_type = 'activated'),
           EXISTS (SELECT 1 FROM mfa_credential_events event
                   WHERE event.credential_id = NEW.credential_id AND event.event_type IN ('disabled','reset'))
      INTO challenge_expires, principal_active, activated, terminal
    FROM mfa_credentials credential
    JOIN users ON users.id = credential.user_id
    JOIN memberships membership
      ON membership.scope_id = credential.scope_id AND membership.user_id = credential.user_id
    WHERE credential.id = NEW.credential_id
      AND credential.user_id = NEW.user_id AND credential.scope_id = NEW.scope_id;

    IF principal_active IS DISTINCT FROM true OR terminal IS DISTINCT FROM false THEN
        RAISE EXCEPTION 'invalid MFA credential event';
    END IF;
    IF NEW.event_type = 'activated' AND (activated OR NEW.occurred_at >= challenge_expires) THEN
        RAISE EXCEPTION 'invalid MFA activation';
    ELSIF NEW.event_type IN ('totp_verified','recovery_verified') AND NOT activated THEN
        RAISE EXCEPTION 'inactive MFA credential';
    ELSIF NEW.event_type IN ('disabled','reset') THEN
        SELECT EXISTS (SELECT 1 FROM mfa_credential_events event
                       WHERE event.credential_id = NEW.credential_id
                         AND event.event_type IN ('totp_verified','recovery_verified')
                         AND event.request_id = NEW.request_id
                         AND event.occurred_at = NEW.occurred_at)
          INTO strong_auth;
        IF NOT activated OR NOT strong_auth THEN
            RAISE EXCEPTION 'MFA deactivation requires strong authentication';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER mfa_credential_events_validate
BEFORE INSERT ON mfa_credential_events
FOR EACH ROW EXECUTE FUNCTION validate_mfa_credential_event();

CREATE FUNCTION validate_mfa_recovery_consumption()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM mfa_credential_events activation
        WHERE activation.credential_id = NEW.credential_id AND activation.event_type = 'activated'
    ) OR EXISTS (
        SELECT 1 FROM mfa_credential_events terminal
        WHERE terminal.credential_id = NEW.credential_id AND terminal.event_type IN ('disabled','reset')
    ) THEN
        RAISE EXCEPTION 'inactive MFA recovery code';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER mfa_recovery_code_consumptions_validate
BEFORE INSERT ON mfa_recovery_code_consumptions
FOR EACH ROW EXECUTE FUNCTION validate_mfa_recovery_consumption();

CREATE FUNCTION validate_mfa_step_up_proof()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    session_valid boolean;
    tenant_active boolean;
    authentication_valid boolean;
BEGIN
    SELECT session.user_id = NEW.actor_user_id AND session.scope_id = NEW.actor_scope_id AND
           session.revoked_at IS NULL AND session.expires_at > NEW.issued_at AND
           (scope.kind = 'platform' OR (scope.kind = 'tenant' AND scope.tenant_id = NEW.tenant_id))
      INTO session_valid
    FROM auth_sessions session
    JOIN access_scopes scope ON scope.id = session.scope_id
    WHERE session.id = NEW.auth_session_id;
    SELECT status = 'active' INTO tenant_active FROM tenants WHERE id = NEW.tenant_id;
    SELECT event.credential_id = NEW.credential_id AND event.user_id = NEW.actor_user_id AND
           event.scope_id = NEW.actor_scope_id AND event.request_id = NEW.request_id AND
           event.occurred_at = NEW.issued_at AND
           ((NEW.authentication_method = 'totp' AND event.event_type = 'totp_verified') OR
            (NEW.authentication_method = 'recovery_code' AND event.event_type = 'recovery_verified'))
      INTO authentication_valid
    FROM mfa_credential_events event WHERE event.id = NEW.authentication_event_id;
    IF session_valid IS DISTINCT FROM true OR tenant_active IS DISTINCT FROM true OR
       authentication_valid IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'invalid MFA step-up proof';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER mfa_step_up_proofs_validate
BEFORE INSERT ON mfa_step_up_proofs
FOR EACH ROW EXECUTE FUNCTION validate_mfa_step_up_proof();

CREATE FUNCTION validate_mfa_step_up_use()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    proof_max_uses smallint;
    proof_expires_at timestamptz;
BEGIN
    SELECT max_uses, expires_at INTO proof_max_uses, proof_expires_at
    FROM mfa_step_up_proofs WHERE id = NEW.proof_id;
    IF NEW.use_ordinal > proof_max_uses OR NEW.used_at >= proof_expires_at THEN
        RAISE EXCEPTION 'invalid MFA step-up use';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER mfa_step_up_uses_validate
BEFORE INSERT ON mfa_step_up_uses
FOR EACH ROW EXECUTE FUNCTION validate_mfa_step_up_use();

CREATE FUNCTION prevent_mfa_fact_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'MFA facts are append-only';
END;
$$;

CREATE TRIGGER mfa_credentials_append_only
BEFORE UPDATE OR DELETE OR TRUNCATE ON mfa_credentials
FOR EACH STATEMENT EXECUTE FUNCTION prevent_mfa_fact_mutation();
CREATE TRIGGER mfa_credential_events_append_only
BEFORE UPDATE OR DELETE OR TRUNCATE ON mfa_credential_events
FOR EACH STATEMENT EXECUTE FUNCTION prevent_mfa_fact_mutation();
CREATE TRIGGER mfa_recovery_codes_append_only
BEFORE UPDATE OR DELETE OR TRUNCATE ON mfa_recovery_codes
FOR EACH STATEMENT EXECUTE FUNCTION prevent_mfa_fact_mutation();
CREATE TRIGGER mfa_recovery_code_consumptions_append_only
BEFORE UPDATE OR DELETE OR TRUNCATE ON mfa_recovery_code_consumptions
FOR EACH STATEMENT EXECUTE FUNCTION prevent_mfa_fact_mutation();
CREATE TRIGGER mfa_step_up_proofs_append_only
BEFORE UPDATE OR DELETE OR TRUNCATE ON mfa_step_up_proofs
FOR EACH STATEMENT EXECUTE FUNCTION prevent_mfa_fact_mutation();
CREATE TRIGGER mfa_step_up_uses_append_only
BEFORE UPDATE OR DELETE OR TRUNCATE ON mfa_step_up_uses
FOR EACH STATEMENT EXECUTE FUNCTION prevent_mfa_fact_mutation();
