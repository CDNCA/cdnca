LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    -- REQUIRED_MIGRATION_107_INTEGRATION_SHA256=7f5dc1a6d88e2ae096564cc29987cc26250cf71748a0cfd51bdcabd2c4ffbfce
    IF (SELECT count(*) FROM schema_migrations) <> 107 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 107 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state IS DISTINCT FROM 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=107 AND migration_id='107_analytics_ingest_watermark_late_revision'
          AND checksum_sha256='5c35e57e9d6ce37af42cf0e3c2241c185017359219728785c952c0e39e8c95c2'
          AND down_checksum_sha256='0e0e31de6e1ae8dac0cec84e219ff90b7caef2533e683bfe25d55ab90f9b7879'
          AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 108 requires the exact verified 107 release head'
            USING ERRCODE='P1080';
    END IF;
END;
$$;

LOCK TABLE notification_outbox, notification_attempts, audit_events,
    access_scopes, memberships, auth_sessions, users, roles,
    role_assignments, role_permissions
IN ACCESS EXCLUSIVE MODE;

ALTER TABLE notification_outbox
    ADD COLUMN generation integer NOT NULL DEFAULT 1 CHECK (generation > 0),
    ADD COLUMN replay_of_outbox_id uuid,
    DROP CONSTRAINT notification_outbox_dedup_key_check,
    DROP CONSTRAINT notification_outbox_status_check,
    DROP CONSTRAINT notification_outbox_check,
    DROP CONSTRAINT notification_outbox_check1,
    DROP CONSTRAINT notification_outbox_event_id_channel_key,
    ADD CONSTRAINT notification_outbox_dedup_key_check CHECK (
        dedup_key ~ '^notification-v[12]-[0-9a-f]{64}$'
    ),
    ADD CONSTRAINT notification_outbox_status_check CHECK (
        status IN ('pending','leased','succeeded','accepted','unknown',
                   'permanent_failed','exhausted','cancelled')
    ),
    ADD CONSTRAINT notification_outbox_state_shape_108 CHECK (
        (status='pending' AND lease_token IS NULL AND lease_expires_at IS NULL AND completed_at IS NULL) OR
        (status='leased' AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL AND completed_at IS NULL) OR
        (status IN ('accepted','unknown') AND lease_token IS NULL AND lease_expires_at IS NULL AND completed_at IS NULL) OR
        (status IN ('succeeded','permanent_failed','exhausted','cancelled') AND
         lease_token IS NULL AND lease_expires_at IS NULL AND completed_at IS NOT NULL)
    ),
    ADD CONSTRAINT notification_outbox_failure_shape_108 CHECK (
        (status IN ('succeeded','accepted') AND last_failure_code IS NULL) OR
        (status='unknown' AND last_failure_code='provider_outcome_unknown') OR
        (status IN ('permanent_failed','exhausted','cancelled') AND last_failure_code IS NOT NULL) OR
        status IN ('pending','leased')
    ),
    ADD CONSTRAINT notification_outbox_event_channel_generation_108_key
        UNIQUE(event_id,channel,generation),
    ADD CONSTRAINT notification_outbox_replay_source_108_fk
        FOREIGN KEY(scope_id,replay_of_outbox_id)
        REFERENCES notification_outbox(scope_id,id) ON DELETE RESTRICT,
    ADD CONSTRAINT notification_outbox_replay_generation_108_check CHECK (
        (generation=1 AND replay_of_outbox_id IS NULL) OR
        (generation>1 AND replay_of_outbox_id IS NOT NULL)
    );

ALTER TABLE notification_attempts
    DROP CONSTRAINT notification_attempts_outcome_check,
    DROP CONSTRAINT notification_attempts_check,
    ADD CONSTRAINT notification_attempts_outcome_check CHECK (
        outcome IN ('leased','succeeded','accepted','unknown','temporary_failure',
                    'permanent_failure','exhausted','lease_expired','cancelled')
    ),
    ADD CONSTRAINT notification_attempts_shape_108 CHECK (
        (outcome='leased' AND failure_code IS NULL AND next_attempt_at IS NULL AND completed_at IS NULL) OR
        (outcome IN ('succeeded','accepted') AND failure_code IS NULL AND next_attempt_at IS NULL AND completed_at IS NOT NULL) OR
        (outcome='unknown' AND failure_code='provider_outcome_unknown' AND next_attempt_at IS NULL AND completed_at IS NOT NULL) OR
        (outcome='temporary_failure' AND failure_code IS NOT NULL AND next_attempt_at IS NOT NULL AND completed_at IS NOT NULL) OR
        (outcome IN ('permanent_failure','exhausted','lease_expired','cancelled') AND
         failure_code IS NOT NULL AND next_attempt_at IS NULL AND completed_at IS NOT NULL)
    );

CREATE TABLE notification_delivery_settlements_108 (
    scope_id uuid NOT NULL,
    outbox_id uuid NOT NULL,
    state text NOT NULL CHECK (state IN (
        'pending','dispatching','retry_wait','accepted','unknown','delivered',
        'permanent_failed','exhausted','cancelled'
    )),
    revision integer NOT NULL CHECK (revision > 0),
    attempt_number integer NOT NULL CHECK (attempt_number >= 0),
    provider text,
    provider_delivery_id text,
    failure_code text,
    retry_at timestamptz,
    accepted_at timestamptz,
    completed_at timestamptz,
    replay_of_outbox_id uuid,
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at) AND updated_at >= created_at),
    PRIMARY KEY(outbox_id),
    UNIQUE(scope_id,outbox_id),
    FOREIGN KEY(scope_id,outbox_id) REFERENCES notification_outbox(scope_id,id) ON DELETE RESTRICT,
    FOREIGN KEY(scope_id,replay_of_outbox_id) REFERENCES notification_outbox(scope_id,id) ON DELETE RESTRICT,
    CHECK (provider IS NULL OR (char_length(provider) BETWEEN 1 AND 64 AND provider=btrim(provider) AND provider !~ '[[:cntrl:]]')),
    CHECK (provider_delivery_id IS NULL OR (char_length(provider_delivery_id) BETWEEN 1 AND 256 AND provider_delivery_id=btrim(provider_delivery_id) AND provider_delivery_id !~ '[[:cntrl:]]')),
    CHECK (failure_code IS NULL OR failure_code ~ '^[a-z][a-z0-9._-]{0,95}$'),
    CHECK (
        (state='pending' AND attempt_number=0 AND provider IS NULL AND provider_delivery_id IS NULL AND failure_code IS NULL AND retry_at IS NULL AND accepted_at IS NULL AND completed_at IS NULL AND replay_of_outbox_id IS NOT NULL) OR
        (state='dispatching' AND attempt_number>0 AND failure_code IS NULL AND retry_at IS NULL AND accepted_at IS NULL AND completed_at IS NULL) OR
        (state='retry_wait' AND attempt_number>0 AND failure_code IS NOT NULL AND retry_at IS NOT NULL AND accepted_at IS NULL AND completed_at IS NULL) OR
        (state='accepted' AND attempt_number>0 AND provider IS NOT NULL AND failure_code IS NULL AND retry_at IS NULL AND accepted_at IS NOT NULL AND completed_at IS NULL) OR
        (state='unknown' AND attempt_number>0 AND failure_code='provider_outcome_unknown' AND retry_at IS NULL AND completed_at IS NULL) OR
        (state='delivered' AND attempt_number>0 AND failure_code IS NULL AND retry_at IS NULL AND completed_at IS NOT NULL) OR
        (state IN ('permanent_failed','exhausted') AND attempt_number>0 AND failure_code IS NOT NULL AND retry_at IS NULL AND completed_at IS NOT NULL) OR
        (state='cancelled' AND failure_code='cancelled' AND retry_at IS NULL AND completed_at IS NOT NULL)
    )
);

CREATE TABLE notification_delivery_facts_108 (
    scope_id uuid NOT NULL,
    outbox_id uuid NOT NULL,
    sequence integer NOT NULL CHECK (sequence > 0),
    attempt_number integer NOT NULL CHECK (attempt_number >= 0),
    fact_kind text NOT NULL CHECK (fact_kind IN (
        'dispatch_started','provider_accepted','provider_unknown','provider_delivered',
        'retry_scheduled','permanent_failed','exhausted','lease_unknown',
        'provider_receipt','cancelled','replay_created'
    )),
    result_state text NOT NULL CHECK (result_state IN (
        'pending','dispatching','retry_wait','accepted','unknown','delivered',
        'permanent_failed','exhausted','cancelled'
    )),
    provider text,
    provider_event_key text,
    provider_delivery_id text,
    failure_code text,
    retry_at timestamptz,
    actor_scope_id uuid,
    actor_user_id uuid,
    operation text,
    request_id text,
    request_digest bytea,
    audit_event_id uuid,
    replay_target_outbox_id uuid,
    observed_at timestamptz NOT NULL CHECK (isfinite(observed_at)),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    PRIMARY KEY(outbox_id,sequence),
    UNIQUE(scope_id,outbox_id,sequence),
    FOREIGN KEY(scope_id,outbox_id) REFERENCES notification_outbox(scope_id,id) ON DELETE RESTRICT,
    FOREIGN KEY(actor_scope_id,actor_user_id) REFERENCES memberships(scope_id,user_id) ON DELETE RESTRICT,
    FOREIGN KEY(audit_event_id) REFERENCES audit_events(id) ON DELETE RESTRICT,
    FOREIGN KEY(scope_id,replay_target_outbox_id) REFERENCES notification_outbox(scope_id,id) ON DELETE RESTRICT,
    CHECK (provider IS NULL OR (char_length(provider) BETWEEN 1 AND 64 AND provider=btrim(provider) AND provider !~ '[[:cntrl:]]')),
    CHECK (provider_event_key IS NULL OR (char_length(provider_event_key) BETWEEN 1 AND 256 AND provider_event_key=btrim(provider_event_key) AND provider_event_key !~ '[[:cntrl:]]')),
    CHECK (provider_delivery_id IS NULL OR (char_length(provider_delivery_id) BETWEEN 1 AND 256 AND provider_delivery_id=btrim(provider_delivery_id) AND provider_delivery_id !~ '[[:cntrl:]]')),
    CHECK (failure_code IS NULL OR failure_code ~ '^[a-z][a-z0-9._-]{0,95}$'),
    CHECK (request_id IS NULL OR (char_length(request_id) BETWEEN 1 AND 128 AND request_id=btrim(request_id) AND request_id !~ '[[:cntrl:]]')),
    CHECK (request_digest IS NULL OR octet_length(request_digest)=32),
    CHECK (
        (operation IS NULL AND actor_scope_id IS NULL AND actor_user_id IS NULL AND request_id IS NULL AND request_digest IS NULL AND audit_event_id IS NULL) OR
        (operation IN ('notification.delivery.cancel','notification.delivery.replay') AND actor_scope_id IS NOT NULL AND actor_user_id IS NOT NULL AND request_id IS NOT NULL AND request_digest IS NOT NULL AND audit_event_id IS NOT NULL)
    )
);

CREATE UNIQUE INDEX notification_delivery_provider_event_108
    ON notification_delivery_facts_108(provider,provider_event_key)
    WHERE provider_event_key IS NOT NULL;
CREATE UNIQUE INDEX notification_delivery_command_fact_108
    ON notification_delivery_facts_108(actor_scope_id,actor_user_id,operation,request_id)
    WHERE operation IS NOT NULL;

CREATE TABLE notification_delivery_command_receipts_108 (
    id uuid PRIMARY KEY,
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    operation text NOT NULL CHECK (operation IN ('notification.delivery.cancel','notification.delivery.replay')),
    request_id text NOT NULL CHECK (char_length(request_id) BETWEEN 1 AND 128 AND request_id=btrim(request_id) AND request_id !~ '[[:cntrl:]]'),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest)=32),
    source_scope_id uuid NOT NULL,
    source_outbox_id uuid NOT NULL,
    result_state text,
    result_outbox_id uuid,
    audit_event_id uuid,
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    completed_at timestamptz,
    UNIQUE(actor_scope_id,actor_user_id,operation,request_id),
    FOREIGN KEY(actor_scope_id,actor_user_id) REFERENCES memberships(scope_id,user_id) ON DELETE RESTRICT,
    FOREIGN KEY(source_scope_id,source_outbox_id) REFERENCES notification_outbox(scope_id,id) ON DELETE RESTRICT,
    FOREIGN KEY(source_scope_id,result_outbox_id) REFERENCES notification_outbox(scope_id,id) ON DELETE RESTRICT,
    FOREIGN KEY(audit_event_id) REFERENCES audit_events(id) ON DELETE RESTRICT,
    CHECK (
        (completed_at IS NULL AND result_state IS NULL AND result_outbox_id IS NULL AND audit_event_id IS NULL) OR
        (completed_at IS NOT NULL AND result_state IN ('cancelled','pending') AND result_outbox_id IS NOT NULL AND audit_event_id IS NOT NULL)
    )
);

CREATE UNIQUE INDEX audit_events_notification_delivery_command_108
    ON audit_events(scope_id,actor_user_id,action,request_id)
    WHERE action IN ('notification.delivery.cancel','notification.delivery.replay');

CREATE FUNCTION guard_notification_delivery_fact_108()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    previous notification_delivery_facts_108%ROWTYPE;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'notification delivery facts are append-only' USING ERRCODE='P1082';
    END IF;
    SELECT * INTO previous FROM notification_delivery_facts_108
    WHERE outbox_id=NEW.outbox_id ORDER BY sequence DESC LIMIT 1 FOR UPDATE;
    IF previous.outbox_id IS NULL THEN
        IF NEW.sequence<>1 OR NEW.result_state NOT IN ('pending','dispatching','cancelled') THEN
            RAISE EXCEPTION 'invalid initial notification delivery fact' USING ERRCODE='P1082';
        END IF;
    ELSIF NEW.sequence<>previous.sequence+1 OR NEW.observed_at<previous.observed_at OR
        NOT (
            (previous.result_state='pending' AND NEW.result_state IN ('dispatching','cancelled')) OR
            (previous.result_state='dispatching' AND NEW.result_state IN ('retry_wait','accepted','unknown','delivered','permanent_failed','exhausted')) OR
            (previous.result_state='retry_wait' AND NEW.result_state IN ('dispatching','cancelled')) OR
            (previous.result_state IN ('accepted','unknown') AND NEW.result_state IN ('delivered','permanent_failed'))
        ) THEN
        RAISE EXCEPTION 'invalid notification delivery fact transition' USING ERRCODE='P1082';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER notification_delivery_facts_guard_108
BEFORE INSERT OR UPDATE OR DELETE ON notification_delivery_facts_108
FOR EACH ROW EXECUTE FUNCTION guard_notification_delivery_fact_108();
CREATE TRIGGER notification_delivery_facts_truncate_108
BEFORE TRUNCATE ON notification_delivery_facts_108
FOR EACH STATEMENT EXECUTE FUNCTION guard_notification_delivery_fact_108();

CREATE FUNCTION validate_notification_delivery_projection_108()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    latest notification_delivery_facts_108%ROWTYPE;
    outbox notification_outbox%ROWTYPE;
    fact_count integer;
    expected_outbox_state text;
BEGIN
    SELECT * INTO latest FROM notification_delivery_facts_108
    WHERE outbox_id=NEW.outbox_id ORDER BY sequence DESC LIMIT 1;
    SELECT count(*) INTO fact_count FROM notification_delivery_facts_108 WHERE outbox_id=NEW.outbox_id;
    SELECT * INTO outbox FROM notification_outbox WHERE scope_id=NEW.scope_id AND id=NEW.outbox_id FOR SHARE;
    expected_outbox_state := CASE NEW.state
        WHEN 'pending' THEN 'pending' WHEN 'dispatching' THEN 'leased'
        WHEN 'retry_wait' THEN 'pending' WHEN 'accepted' THEN 'accepted'
        WHEN 'unknown' THEN 'unknown' WHEN 'delivered' THEN 'succeeded'
        ELSE NEW.state END;
    IF latest.outbox_id IS NULL OR outbox.id IS NULL OR
       latest.scope_id IS DISTINCT FROM NEW.scope_id OR latest.sequence<>NEW.revision OR
       fact_count<>NEW.revision OR latest.result_state IS DISTINCT FROM NEW.state OR
       latest.attempt_number IS DISTINCT FROM NEW.attempt_number OR
       outbox.status IS DISTINCT FROM expected_outbox_state OR
       outbox.replay_of_outbox_id IS DISTINCT FROM NEW.replay_of_outbox_id THEN
        RAISE EXCEPTION 'notification delivery projection does not match latest fact' USING ERRCODE='P1082';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER notification_delivery_projection_final_108
AFTER INSERT OR UPDATE ON notification_delivery_settlements_108
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_notification_delivery_projection_108();

CREATE FUNCTION guard_notification_delivery_projection_108()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' OR TG_OP='TRUNCATE' THEN
        RAISE EXCEPTION 'notification delivery settlements are immutable' USING ERRCODE='P1082';
    END IF;
    IF TG_OP='UPDATE' AND (
        NEW.scope_id IS DISTINCT FROM OLD.scope_id OR NEW.outbox_id IS DISTINCT FROM OLD.outbox_id OR
        NEW.created_at IS DISTINCT FROM OLD.created_at OR NEW.replay_of_outbox_id IS DISTINCT FROM OLD.replay_of_outbox_id OR
        OLD.state IN ('delivered','permanent_failed','exhausted','cancelled') OR
        NEW.revision<>OLD.revision+1 OR NEW.updated_at<OLD.updated_at
    ) THEN
        RAISE EXCEPTION 'invalid notification delivery projection mutation' USING ERRCODE='P1082';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER notification_delivery_projection_guard_108
BEFORE UPDATE OR DELETE ON notification_delivery_settlements_108
FOR EACH ROW EXECUTE FUNCTION guard_notification_delivery_projection_108();
CREATE TRIGGER notification_delivery_projection_truncate_108
BEFORE TRUNCATE ON notification_delivery_settlements_108
FOR EACH STATEMENT EXECUTE FUNCTION guard_notification_delivery_projection_108();

CREATE FUNCTION guard_notification_delivery_command_receipt_108()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='INSERT' THEN
        RETURN NEW;
    END IF;
    IF TG_OP<>'UPDATE' OR OLD.completed_at IS NOT NULL OR NEW.completed_at IS NULL OR
       ROW(NEW.id,NEW.actor_scope_id,NEW.actor_user_id,NEW.operation,NEW.request_id,
           NEW.request_digest,NEW.source_scope_id,NEW.source_outbox_id,NEW.created_at)
       IS DISTINCT FROM
       ROW(OLD.id,OLD.actor_scope_id,OLD.actor_user_id,OLD.operation,OLD.request_id,
           OLD.request_digest,OLD.source_scope_id,OLD.source_outbox_id,OLD.created_at) THEN
        RAISE EXCEPTION 'notification delivery command receipts are immutable' USING ERRCODE='P1082';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER notification_delivery_command_receipts_guard_108
BEFORE INSERT OR UPDATE OR DELETE ON notification_delivery_command_receipts_108
FOR EACH ROW EXECUTE FUNCTION guard_notification_delivery_command_receipt_108();
CREATE TRIGGER notification_delivery_command_receipts_truncate_108
BEFORE TRUNCATE ON notification_delivery_command_receipts_108
FOR EACH STATEMENT EXECUTE FUNCTION guard_notification_delivery_command_receipt_108();

CREATE FUNCTION guard_notification_outbox_transition_108()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.status IS DISTINCT FROM OLD.status AND NOT (
        (OLD.status='pending' AND NEW.status IN ('leased','cancelled')) OR
        (OLD.status='leased' AND NEW.status IN ('pending','succeeded','accepted','unknown','permanent_failed','exhausted')) OR
        (OLD.status IN ('accepted','unknown') AND NEW.status IN ('succeeded','permanent_failed'))
    ) THEN
        RAISE EXCEPTION 'invalid notification outbox state transition' USING ERRCODE='P1082';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER notification_outbox_transition_108
BEFORE UPDATE ON notification_outbox
FOR EACH ROW EXECUTE FUNCTION guard_notification_outbox_transition_108();

CREATE OR REPLACE FUNCTION protect_notification_outbox_payload()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.status IN ('succeeded','permanent_failed','exhausted','cancelled') THEN
        RAISE EXCEPTION 'completed notification outbox is immutable';
    END IF;
    IF ROW(NEW.id,NEW.scope_id,NEW.event_id,NEW.channel,NEW.template_id,
           NEW.template_version,NEW.subject,NEW.body,NEW.dedup_key,NEW.generation,
           NEW.replay_of_outbox_id,NEW.created_at)
       IS DISTINCT FROM
       ROW(OLD.id,OLD.scope_id,OLD.event_id,OLD.channel,OLD.template_id,
           OLD.template_version,OLD.subject,OLD.body,OLD.dedup_key,OLD.generation,
           OLD.replay_of_outbox_id,OLD.created_at) THEN
        RAISE EXCEPTION 'notification outbox payload is immutable';
    END IF;
    RETURN NEW;
END;
$$;

REVOKE ALL ON notification_delivery_settlements_108 FROM PUBLIC;
REVOKE ALL ON notification_delivery_facts_108 FROM PUBLIC;
REVOKE ALL ON notification_delivery_command_receipts_108 FROM PUBLIC;
REVOKE ALL ON FUNCTION guard_notification_delivery_fact_108() FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_notification_delivery_projection_108() FROM PUBLIC;
REVOKE ALL ON FUNCTION guard_notification_delivery_projection_108() FROM PUBLIC;
REVOKE ALL ON FUNCTION guard_notification_delivery_command_receipt_108() FROM PUBLIC;
REVOKE ALL ON FUNCTION guard_notification_outbox_transition_108() FROM PUBLIC;

-- Runtime authorization remains fail closed and is rechecked for every command.
COMMENT ON TABLE notification_delivery_command_receipts_108 IS
    'Cancel/replay requires a current platform session and system_configuration.manage; provider acceptance is never final delivery.';
