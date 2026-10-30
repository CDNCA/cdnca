LOCK TABLE schema_migrations,
    package_monitor_alert_heads,
    package_monitor_transition_facts,
    auth_sessions,
    audit_events
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 120 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 120 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state IS DISTINCT FROM 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=120 AND migration_id='120_certificate_publication_results'
          AND checksum_sha256='8bad0019496e9f47fa92c66bf1b432d2ded681f9049717ef830cd4364923e9f0'
          AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 121 requires the exact verified 120 release head'
            USING ERRCODE='P1210';
    END IF;
END;
$$;

CREATE TABLE package_monitor_alert_acknowledgement_receipts (
    id uuid PRIMARY KEY,
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    actor_session_id uuid NOT NULL,
    action_code text NOT NULL CHECK (action_code = 'package_monitor.alert.acknowledge'),
    idempotency_key text NOT NULL CHECK (
        octet_length(idempotency_key) BETWEEN 1 AND 128 AND
        idempotency_key = btrim(idempotency_key) AND idempotency_key !~ '[[:cntrl:]]'
    ),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    response_body bytea CHECK (response_body IS NULL OR octet_length(response_body) BETWEEN 2 AND 1048576),
    completed_at timestamptz CHECK (completed_at IS NULL OR isfinite(completed_at)),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    UNIQUE (actor_scope_id, actor_user_id, action_code, idempotency_key),
    FOREIGN KEY (actor_session_id,actor_scope_id,actor_user_id)
        REFERENCES auth_sessions(id,scope_id,user_id) ON DELETE RESTRICT,
    CHECK ((completed_at IS NULL AND response_body IS NULL) OR
           (completed_at IS NOT NULL AND response_body IS NOT NULL))
);

CREATE TABLE package_monitor_alert_acknowledgement_facts (
    id uuid PRIMARY KEY,
    receipt_id uuid NOT NULL UNIQUE,
    alert_id uuid NOT NULL,
    alert_revision bigint NOT NULL CHECK (alert_revision > 0),
    tenant_scope_id uuid NOT NULL,
    subscription_id uuid NOT NULL,
    owner_user_id uuid NOT NULL,
    actor_scope_id uuid NOT NULL,
    actor_scope_kind text NOT NULL CHECK (actor_scope_kind IN ('tenant','platform')),
    actor_user_id uuid NOT NULL,
    actor_session_id uuid NOT NULL,
    action_code text NOT NULL CHECK (action_code = 'package_monitor.alert.acknowledge'),
    idempotency_key text NOT NULL CHECK (
        octet_length(idempotency_key) BETWEEN 1 AND 128 AND
        idempotency_key = btrim(idempotency_key) AND idempotency_key !~ '[[:cntrl:]]'
    ),
    request_id text NOT NULL CHECK (
        octet_length(request_id) BETWEEN 1 AND 128 AND
        request_id = btrim(request_id) AND request_id !~ '[[:cntrl:]]'
    ),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    state text NOT NULL CHECK (state = 'triggered'),
    note text CHECK (
        note IS NULL OR (octet_length(note) BETWEEN 1 AND 2000 AND note = btrim(note) AND note !~ '[[:cntrl:]]')
    ),
    acknowledged_at timestamptz NOT NULL CHECK (isfinite(acknowledged_at)),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    UNIQUE (id, alert_id, alert_revision),
    UNIQUE (alert_id, alert_revision),
    FOREIGN KEY (alert_id,alert_revision)
        REFERENCES package_monitor_transition_facts(alert_id,revision) ON DELETE RESTRICT,
    FOREIGN KEY (receipt_id)
        REFERENCES package_monitor_alert_acknowledgement_receipts(id) ON DELETE RESTRICT,
    FOREIGN KEY (actor_session_id,actor_scope_id,actor_user_id)
        REFERENCES auth_sessions(id,scope_id,user_id) ON DELETE RESTRICT,
    FOREIGN KEY (actor_scope_id,actor_user_id)
        REFERENCES memberships(scope_id,user_id) ON DELETE RESTRICT,
    CHECK ((actor_scope_kind='tenant' AND actor_scope_id=tenant_scope_id) OR actor_scope_kind='platform')
);

CREATE TABLE package_monitor_alert_acknowledgement_heads (
    alert_id uuid PRIMARY KEY,
    alert_revision bigint NOT NULL CHECK (alert_revision > 0),
    tenant_scope_id uuid NOT NULL,
    acknowledgement_id uuid NOT NULL,
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    actor_session_id uuid NOT NULL,
    note text CHECK (
        note IS NULL OR (octet_length(note) BETWEEN 1 AND 2000 AND note = btrim(note) AND note !~ '[[:cntrl:]]')
    ),
    acknowledged_at timestamptz NOT NULL CHECK (isfinite(acknowledged_at)),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at)),
    FOREIGN KEY (acknowledgement_id,alert_id,alert_revision)
        REFERENCES package_monitor_alert_acknowledgement_facts(id,alert_id,alert_revision) ON DELETE RESTRICT,
    FOREIGN KEY (actor_session_id,actor_scope_id,actor_user_id)
        REFERENCES auth_sessions(id,scope_id,user_id) ON DELETE RESTRICT
);

CREATE FUNCTION validate_package_monitor_alert_acknowledgement_fact_121()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    current_revision bigint;
    current_state text;
    current_tenant_scope uuid;
    current_subscription uuid;
    current_owner uuid;
    actor_kind text;
BEGIN
    SELECT head.revision,head.state,head.tenant_scope_id,head.subscription_id,head.owner_user_id
    INTO current_revision,current_state,current_tenant_scope,current_subscription,current_owner
    FROM package_monitor_alert_heads AS head
    WHERE head.id=NEW.alert_id
    FOR KEY SHARE;
    IF NOT FOUND OR current_revision IS DISTINCT FROM NEW.alert_revision OR
       current_state IS DISTINCT FROM 'triggered' OR
       current_tenant_scope IS DISTINCT FROM NEW.tenant_scope_id OR
       current_subscription IS DISTINCT FROM NEW.subscription_id OR
       current_owner IS DISTINCT FROM NEW.owner_user_id THEN
        RAISE EXCEPTION 'package monitor alert acknowledgement must target the current triggered revision'
            USING ERRCODE='23514';
    END IF;
    SELECT scope.kind INTO actor_kind FROM access_scopes AS scope WHERE scope.id=NEW.actor_scope_id;
    IF actor_kind IS DISTINCT FROM NEW.actor_scope_kind OR
       (NEW.actor_scope_kind='tenant' AND NEW.actor_scope_id IS DISTINCT FROM NEW.tenant_scope_id) OR
       (NEW.actor_scope_kind='platform' AND NEW.actor_scope_id=NEW.tenant_scope_id) THEN
        RAISE EXCEPTION 'package monitor alert acknowledgement actor scope is inconsistent'
            USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER package_monitor_alert_acknowledgement_facts_validate_121
BEFORE INSERT ON package_monitor_alert_acknowledgement_facts
FOR EACH ROW EXECUTE FUNCTION validate_package_monitor_alert_acknowledgement_fact_121();

CREATE INDEX package_monitor_alert_acknowledgement_heads_tenant_121
    ON package_monitor_alert_acknowledgement_heads (tenant_scope_id, acknowledged_at DESC, alert_id);

CREATE FUNCTION protect_package_monitor_alert_acknowledgement_fact_121()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'package monitor alert acknowledgement facts are append-only'
        USING ERRCODE='55000';
END;
$$;

CREATE TRIGGER package_monitor_alert_acknowledgement_facts_append_only_121
BEFORE UPDATE OR DELETE ON package_monitor_alert_acknowledgement_facts
FOR EACH ROW EXECUTE FUNCTION protect_package_monitor_alert_acknowledgement_fact_121();

CREATE TRIGGER package_monitor_alert_acknowledgement_facts_no_truncate_121
BEFORE TRUNCATE ON package_monitor_alert_acknowledgement_facts
FOR EACH STATEMENT EXECUTE FUNCTION protect_package_monitor_alert_acknowledgement_fact_121();

CREATE FUNCTION protect_package_monitor_alert_acknowledgement_receipt_121()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        RETURN NEW;
    END IF;
    IF TG_OP = 'DELETE' OR TG_OP <> 'UPDATE' OR
       ROW(NEW.id,NEW.actor_scope_id,NEW.actor_user_id,NEW.actor_session_id,NEW.action_code,
           NEW.idempotency_key,NEW.request_digest,NEW.created_at) IS DISTINCT FROM
       ROW(OLD.id,OLD.actor_scope_id,OLD.actor_user_id,OLD.actor_session_id,OLD.action_code,
           OLD.idempotency_key,OLD.request_digest,OLD.created_at) OR
       OLD.completed_at IS NOT NULL OR NEW.completed_at IS NULL OR NEW.response_body IS NULL THEN
        RAISE EXCEPTION 'package monitor alert acknowledgement receipt is immutable'
            USING ERRCODE='55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER package_monitor_alert_acknowledgement_receipts_protect_121
BEFORE INSERT OR UPDATE OR DELETE ON package_monitor_alert_acknowledgement_receipts
FOR EACH ROW EXECUTE FUNCTION protect_package_monitor_alert_acknowledgement_receipt_121();

CREATE FUNCTION validate_package_monitor_alert_acknowledgement_head_121()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP <> 'INSERT' OR NOT EXISTS (
        SELECT 1 FROM package_monitor_alert_acknowledgement_facts fact
        WHERE fact.id=NEW.acknowledgement_id AND fact.alert_id=NEW.alert_id
          AND fact.alert_revision=NEW.alert_revision
          AND fact.tenant_scope_id=NEW.tenant_scope_id
          AND fact.actor_scope_id=NEW.actor_scope_id
          AND fact.actor_user_id=NEW.actor_user_id
          AND fact.actor_session_id=NEW.actor_session_id
          AND fact.note IS NOT DISTINCT FROM NEW.note
          AND fact.acknowledged_at=NEW.acknowledged_at
    ) THEN
        RAISE EXCEPTION 'package monitor alert acknowledgement current projection is inconsistent'
            USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER package_monitor_alert_acknowledgement_heads_validate_121
BEFORE INSERT OR UPDATE ON package_monitor_alert_acknowledgement_heads
FOR EACH ROW EXECUTE FUNCTION validate_package_monitor_alert_acknowledgement_head_121();

CREATE FUNCTION validate_package_monitor_alert_acknowledgement_audit_121()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM audit_events event
        WHERE event.scope_id=NEW.actor_scope_id AND event.actor_user_id=NEW.actor_user_id
          AND event.action='package_monitor.alert.acknowledge'
          AND event.resource_type='package_monitor_alert' AND event.resource_id=NEW.alert_id::text
          AND event.request_id=NEW.request_id AND event.result='success'
          AND event.payload->>'acknowledgement_id'=NEW.id::text
          AND (event.payload->>'alert_revision')::bigint=NEW.alert_revision
    ) THEN
        RAISE EXCEPTION 'package monitor alert acknowledgement audit is missing or inconsistent'
            USING ERRCODE='23514';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER package_monitor_alert_acknowledgement_audit_validate_121
AFTER INSERT ON package_monitor_alert_acknowledgement_facts
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
EXECUTE FUNCTION validate_package_monitor_alert_acknowledgement_audit_121();

REVOKE ALL ON TABLE package_monitor_alert_acknowledgement_receipts,
    package_monitor_alert_acknowledgement_facts,
    package_monitor_alert_acknowledgement_heads FROM PUBLIC;
REVOKE ALL ON FUNCTION protect_package_monitor_alert_acknowledgement_fact_121() FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_package_monitor_alert_acknowledgement_fact_121() FROM PUBLIC;
REVOKE ALL ON FUNCTION protect_package_monitor_alert_acknowledgement_receipt_121() FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_package_monitor_alert_acknowledgement_head_121() FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_package_monitor_alert_acknowledgement_audit_121() FROM PUBLIC;
