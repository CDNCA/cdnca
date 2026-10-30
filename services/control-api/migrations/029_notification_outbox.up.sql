CREATE TABLE notification_templates (
    template_id text NOT NULL CHECK (
        template_id ~ '^[a-z][a-z0-9._-]{0,95}$'
    ),
    version bigint NOT NULL CHECK (version > 0),
    channel text NOT NULL CHECK (channel IN ('sms', 'email')),
    subject text NOT NULL DEFAULT '',
    body text NOT NULL CHECK (body <> ''),
    variables text[] NOT NULL DEFAULT '{}'::text[] CHECK (
        cardinality(variables) <= 32 AND array_position(variables, NULL) IS NULL
    ),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (template_id, version, channel),
    CHECK (
        (channel = 'sms' AND subject = '' AND octet_length(body) <= 8192) OR
        (channel = 'email' AND octet_length(subject) BETWEEN 1 AND 2048 AND
         octet_length(body) <= 131072)
    )
);

CREATE TABLE notification_channel_settings (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    sms_enabled boolean NOT NULL DEFAULT false,
    email_enabled boolean NOT NULL DEFAULT false,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    updated_at timestamptz NOT NULL
);

INSERT INTO notification_channel_settings (
    singleton, sms_enabled, email_enabled, revision, updated_at
) VALUES (true, false, false, 1, CURRENT_TIMESTAMP);

CREATE TABLE notification_subscriptions (
    scope_id uuid NOT NULL,
    user_id uuid NOT NULL,
    event_type text NOT NULL CHECK (
        event_type ~ '^[a-z][a-z0-9._-]{0,95}$'
    ),
    sms_enabled boolean NOT NULL DEFAULT false,
    email_enabled boolean NOT NULL DEFAULT false,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (scope_id, user_id, event_type),
    FOREIGN KEY (scope_id, user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE CASCADE
);

CREATE TABLE notification_events (
    id uuid PRIMARY KEY,
    scope_id uuid NOT NULL,
    recipient_user_id uuid NOT NULL,
    source_event_id text NOT NULL CHECK (
        char_length(source_event_id) BETWEEN 1 AND 256 AND
        source_event_id = btrim(source_event_id)
    ),
    event_type text NOT NULL CHECK (
        event_type ~ '^[a-z][a-z0-9._-]{0,95}$'
    ),
    delivery_policy text NOT NULL CHECK (
        delivery_policy IN ('tenant_subscribed', 'system_required')
    ),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    created_at timestamptz NOT NULL,
    UNIQUE (scope_id, id),
    UNIQUE (scope_id, recipient_user_id, source_event_id, event_type),
    FOREIGN KEY (scope_id, recipient_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT
);

CREATE TABLE notification_outbox (
    id uuid PRIMARY KEY,
    scope_id uuid NOT NULL,
    event_id uuid NOT NULL,
    channel text NOT NULL CHECK (channel IN ('sms', 'email')),
    template_id text NOT NULL,
    template_version bigint NOT NULL,
    subject text NOT NULL DEFAULT '',
    body text NOT NULL,
    dedup_key text NOT NULL UNIQUE CHECK (
        dedup_key ~ '^notification-v1-[0-9a-f]{64}$'
    ),
    status text NOT NULL DEFAULT 'pending' CHECK (
        status IN ('pending', 'leased', 'succeeded', 'permanent_failed', 'exhausted')
    ),
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    available_at timestamptz NOT NULL,
    lease_token uuid,
    lease_expires_at timestamptz,
    last_failure_code text CHECK (
        last_failure_code IS NULL OR
        last_failure_code ~ '^[a-z][a-z0-9._-]{0,95}$'
    ),
    completed_at timestamptz,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    UNIQUE (scope_id, id),
    UNIQUE (event_id, channel),
    FOREIGN KEY (scope_id, event_id)
        REFERENCES notification_events(scope_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (template_id, template_version, channel)
        REFERENCES notification_templates(template_id, version, channel) ON DELETE RESTRICT,
    CHECK (
        (channel = 'sms' AND subject = '' AND octet_length(body) <= 2048) OR
        (channel = 'email' AND char_length(subject) BETWEEN 1 AND 200 AND
         octet_length(body) <= 65536)
    ),
    CHECK (
        (status = 'pending' AND lease_token IS NULL AND lease_expires_at IS NULL AND completed_at IS NULL) OR
        (status = 'leased' AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL AND completed_at IS NULL) OR
        (status IN ('succeeded', 'permanent_failed', 'exhausted') AND
         lease_token IS NULL AND lease_expires_at IS NULL AND completed_at IS NOT NULL)
    ),
    CHECK (
        (status = 'succeeded' AND last_failure_code IS NULL) OR
        (status IN ('permanent_failed', 'exhausted') AND last_failure_code IS NOT NULL) OR
        status IN ('pending', 'leased')
    )
);

CREATE INDEX notification_outbox_pending_idx
    ON notification_outbox (available_at, id) WHERE status = 'pending';

CREATE INDEX notification_outbox_lease_expiry_idx
    ON notification_outbox (lease_expires_at, id) WHERE status = 'leased';

CREATE INDEX notification_outbox_scope_created_idx
    ON notification_outbox (scope_id, created_at DESC, id DESC);

CREATE TABLE notification_attempts (
    outbox_id uuid NOT NULL,
    scope_id uuid NOT NULL,
    attempt_number integer NOT NULL CHECK (attempt_number > 0),
    lease_token uuid NOT NULL,
    lease_expires_at timestamptz NOT NULL,
    outcome text NOT NULL CHECK (
        outcome IN ('leased', 'succeeded', 'temporary_failure', 'permanent_failure', 'exhausted', 'lease_expired')
    ),
    failure_code text CHECK (
        failure_code IS NULL OR failure_code ~ '^[a-z][a-z0-9._-]{0,95}$'
    ),
    next_attempt_at timestamptz,
    claimed_at timestamptz NOT NULL,
    completed_at timestamptz,
    PRIMARY KEY (outbox_id, attempt_number),
    UNIQUE (lease_token),
    FOREIGN KEY (scope_id, outbox_id)
        REFERENCES notification_outbox(scope_id, id) ON DELETE RESTRICT,
    CHECK (
        (outcome = 'leased' AND failure_code IS NULL AND next_attempt_at IS NULL AND completed_at IS NULL) OR
        (outcome = 'succeeded' AND failure_code IS NULL AND next_attempt_at IS NULL AND completed_at IS NOT NULL) OR
        (outcome = 'temporary_failure' AND failure_code IS NOT NULL AND next_attempt_at IS NOT NULL AND completed_at IS NOT NULL) OR
        (outcome IN ('permanent_failure', 'exhausted', 'lease_expired') AND
         failure_code IS NOT NULL AND next_attempt_at IS NULL AND completed_at IS NOT NULL)
    )
);

CREATE INDEX notification_attempts_scope_claimed_idx
    ON notification_attempts (scope_id, claimed_at DESC, outbox_id);

CREATE FUNCTION protect_notification_attempt_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF ROW(NEW.outbox_id, NEW.scope_id, NEW.attempt_number, NEW.lease_token,
           NEW.lease_expires_at, NEW.claimed_at)
       IS DISTINCT FROM
       ROW(OLD.outbox_id, OLD.scope_id, OLD.attempt_number, OLD.lease_token,
           OLD.lease_expires_at, OLD.claimed_at) OR
       OLD.outcome <> 'leased' OR NEW.outcome = 'leased' THEN
        RAISE EXCEPTION 'notification attempt transition is invalid';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER notification_attempt_transition_guard
BEFORE UPDATE ON notification_attempts
FOR EACH ROW EXECUTE FUNCTION protect_notification_attempt_transition();

CREATE FUNCTION prevent_notification_immutable_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'notification record is immutable';
END;
$$;

CREATE TRIGGER notification_templates_immutable
BEFORE UPDATE OR DELETE ON notification_templates
FOR EACH ROW EXECUTE FUNCTION prevent_notification_immutable_mutation();

CREATE TRIGGER notification_templates_truncate_immutable
BEFORE TRUNCATE ON notification_templates
FOR EACH STATEMENT EXECUTE FUNCTION prevent_notification_immutable_mutation();

CREATE TRIGGER notification_events_immutable
BEFORE UPDATE OR DELETE ON notification_events
FOR EACH ROW EXECUTE FUNCTION prevent_notification_immutable_mutation();

CREATE TRIGGER notification_events_truncate_immutable
BEFORE TRUNCATE ON notification_events
FOR EACH STATEMENT EXECUTE FUNCTION prevent_notification_immutable_mutation();

CREATE TRIGGER notification_outbox_delete_immutable
BEFORE DELETE ON notification_outbox
FOR EACH ROW EXECUTE FUNCTION prevent_notification_immutable_mutation();

CREATE TRIGGER notification_outbox_truncate_immutable
BEFORE TRUNCATE ON notification_outbox
FOR EACH STATEMENT EXECUTE FUNCTION prevent_notification_immutable_mutation();

CREATE FUNCTION protect_notification_outbox_payload()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.status IN ('succeeded', 'permanent_failed', 'exhausted') THEN
        RAISE EXCEPTION 'completed notification outbox is immutable';
    END IF;
    IF ROW(NEW.id, NEW.scope_id, NEW.event_id, NEW.channel, NEW.template_id,
           NEW.template_version, NEW.subject, NEW.body, NEW.dedup_key, NEW.created_at)
       IS DISTINCT FROM
       ROW(OLD.id, OLD.scope_id, OLD.event_id, OLD.channel, OLD.template_id,
           OLD.template_version, OLD.subject, OLD.body, OLD.dedup_key, OLD.created_at) THEN
        RAISE EXCEPTION 'notification outbox payload is immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER notification_outbox_payload_immutable
BEFORE UPDATE ON notification_outbox
FOR EACH ROW EXECUTE FUNCTION protect_notification_outbox_payload();
