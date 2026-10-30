CREATE TABLE acme_issuance_operations (
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    operation_id text NOT NULL CHECK (
        operation_id = btrim(operation_id)
        AND octet_length(operation_id) BETWEEN 1 AND 200
        AND operation_id !~ '[[:cntrl:]]'
    ),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    request_snapshot jsonb NOT NULL CHECK (
        jsonb_typeof(request_snapshot) = 'object'
        AND octet_length(request_snapshot::text) BETWEEN 2 AND 65536
    ),
    directory_url text NOT NULL CHECK (
        directory_url LIKE 'https://%'
        AND octet_length(directory_url) BETWEEN 10 AND 4096
        AND directory_url !~ '[[:cntrl:]]'
    ),
    certificate_key_ref text NOT NULL CHECK (
        certificate_key_ref = btrim(certificate_key_ref)
        AND octet_length(certificate_key_ref) BETWEEN 1 AND 200
        AND certificate_key_ref !~ '[[:cntrl:]]'
    ),
    created_at timestamptz NOT NULL,
    CHECK (
        request_snapshot ? 'TenantID'
        AND request_snapshot ? 'ScopeID'
        AND request_snapshot ? 'ActorUserID'
    ),
    CHECK (request_snapshot ->> 'ScopeID' = tenant_scope_id::text),
    CHECK (request_snapshot ->> 'OperationID' = operation_id),
    CHECK (request_snapshot ->> 'DirectoryURL' = directory_url),
    CHECK (request_snapshot ->> 'CertificateKeyRef' = certificate_key_ref),
    PRIMARY KEY (tenant_scope_id, operation_id)
);

CREATE TABLE acme_issuance_operation_events (
    tenant_scope_id uuid NOT NULL,
    operation_id text NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    event_type text NOT NULL CHECK (event_type IN (
        'claim_created', 'lease_taken_over', 'account_registered', 'order_intent',
        'order_rejected', 'order_created', 'authorizing', 'authorization_ready',
        'finalize_intent', 'certificate_saved', 'completed', 'retry_scheduled', 'failed'
    )),
    phase text NOT NULL CHECK (phase IN (
        'claimed', 'ordered', 'authorizing', 'ready', 'finalizing',
        'certificate_saved', 'completed'
    )),
    status text NOT NULL CHECK (status IN ('active', 'retry_wait', 'completed', 'failed')),
    fence_token uuid NOT NULL,
    order_intent_pending boolean NOT NULL DEFAULT false,
    lease_token uuid,
    lease_expires_at timestamptz,
    next_reconcile_at timestamptz,
    account_uri text CHECK (account_uri IS NULL OR (
        account_uri LIKE 'https://%' AND octet_length(account_uri) <= 4096
        AND account_uri !~ '[[:cntrl:]]'
    )),
    order_url text CHECK (order_url IS NULL OR (
        order_url LIKE 'https://%' AND octet_length(order_url) <= 4096
        AND order_url !~ '[[:cntrl:]]'
    )),
    finalize_url text CHECK (finalize_url IS NULL OR (
        finalize_url LIKE 'https://%' AND octet_length(finalize_url) <= 4096
        AND finalize_url !~ '[[:cntrl:]]'
    )),
    authorization_urls text[] NOT NULL DEFAULT '{}' CHECK (cardinality(authorization_urls) <= 100),
    certificate_url text CHECK (certificate_url IS NULL OR (
        certificate_url LIKE 'https://%' AND octet_length(certificate_url) <= 4096
        AND certificate_url !~ '[[:cntrl:]]'
    )),
    certificate_spki_sha256 bytea CHECK (
        certificate_spki_sha256 IS NULL OR octet_length(certificate_spki_sha256) = 32
    ),
    leaf_fingerprint_sha256 bytea CHECK (
        leaf_fingerprint_sha256 IS NULL OR octet_length(leaf_fingerprint_sha256) = 32
    ),
    failure_code text CHECK (failure_code IS NULL OR failure_code ~ '^[a-z0-9_]{1,128}$'),
    occurred_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_scope_id, operation_id, revision),
    FOREIGN KEY (tenant_scope_id, operation_id)
        REFERENCES acme_issuance_operations(tenant_scope_id, operation_id) ON DELETE RESTRICT,
    CHECK (
        (NOT order_intent_pending OR order_url IS NULL)
        AND (order_url IS NULL OR NOT order_intent_pending)
        AND (
            (status = 'active' AND lease_token IS NOT NULL AND lease_expires_at > occurred_at
                AND next_reconcile_at IS NULL AND failure_code IS NULL)
            OR
            (status = 'retry_wait' AND lease_token IS NULL AND lease_expires_at IS NULL
                AND next_reconcile_at > occurred_at AND failure_code IS NOT NULL)
            OR
            (status = 'completed' AND phase = 'completed' AND lease_token IS NULL
                AND lease_expires_at IS NULL AND next_reconcile_at IS NULL AND failure_code IS NULL
                AND certificate_url IS NOT NULL AND certificate_spki_sha256 IS NOT NULL
                AND leaf_fingerprint_sha256 IS NOT NULL)
            OR
            (status = 'failed' AND lease_token IS NULL AND lease_expires_at IS NULL
                AND next_reconcile_at IS NULL AND failure_code IS NOT NULL)
        )
    )
);

CREATE INDEX acme_issuance_operation_events_reconcile_idx
    ON acme_issuance_operation_events (status, next_reconcile_at, lease_expires_at, occurred_at)
    INCLUDE (tenant_scope_id, operation_id, revision, phase);

CREATE TABLE acme_issuance_challenge_attempts (
    tenant_scope_id uuid NOT NULL,
    operation_id text NOT NULL,
    attempt_id uuid NOT NULL,
    attempt_number integer NOT NULL CHECK (attempt_number > 0),
    authorization_url text NOT NULL CHECK (
        authorization_url LIKE 'https://%' AND octet_length(authorization_url) <= 4096
        AND authorization_url !~ '[[:cntrl:]]'
    ),
    challenge_url text NOT NULL CHECK (
        challenge_url LIKE 'https://%' AND octet_length(challenge_url) <= 4096
        AND challenge_url !~ '[[:cntrl:]]'
    ),
    challenge_type text NOT NULL CHECK (challenge_type IN ('http-01', 'dns-01')),
    identifier text NOT NULL CHECK (
        identifier = lower(identifier) AND identifier = btrim(identifier)
        AND octet_length(identifier) BETWEEN 3 AND 253 AND identifier !~ '[[:cntrl:]]'
    ),
    wildcard boolean NOT NULL,
    record_name text NOT NULL CHECK (
        record_name = lower(record_name) AND record_name = btrim(record_name)
        AND octet_length(record_name) BETWEEN 1 AND 255 AND record_name !~ '[[:cntrl:]]'
    ),
    token text NOT NULL CHECK (
        octet_length(token) BETWEEN 1 AND 512 AND token !~ '[[:space:][:cntrl:]]'
    ),
    exact_value text NOT NULL CHECK (
        octet_length(exact_value) BETWEEN 1 AND 4096 AND exact_value !~ '[[:cntrl:]]'
    ),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_scope_id, operation_id, attempt_id),
    UNIQUE (tenant_scope_id, operation_id, authorization_url, attempt_number),
    FOREIGN KEY (tenant_scope_id, operation_id)
        REFERENCES acme_issuance_operations(tenant_scope_id, operation_id) ON DELETE RESTRICT,
    CHECK (
        (challenge_type = 'dns-01' AND record_name = '_acme-challenge.' || identifier || '.')
        OR
        (challenge_type = 'http-01' AND record_name = identifier)
    ),
    CHECK (NOT wildcard OR challenge_type = 'dns-01')
);

CREATE TABLE acme_issuance_challenge_events (
    tenant_scope_id uuid NOT NULL,
    operation_id text NOT NULL,
    attempt_id uuid NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    state text NOT NULL CHECK (state IN ('intent', 'published', 'cleanup_claimed', 'cleaned')),
    lease_token uuid NOT NULL,
    occurred_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_scope_id, operation_id, attempt_id, revision),
    FOREIGN KEY (tenant_scope_id, operation_id, attempt_id)
        REFERENCES acme_issuance_challenge_attempts(tenant_scope_id, operation_id, attempt_id)
        ON DELETE RESTRICT
);

CREATE INDEX acme_issuance_challenge_cleanup_idx
    ON acme_issuance_challenge_events (state, occurred_at)
    INCLUDE (tenant_scope_id, operation_id, attempt_id, revision);

CREATE FUNCTION protect_acme_issuance_facts()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'ACME issuance facts are append-only' USING ERRCODE = 'P0001';
END;
$$;

CREATE FUNCTION validate_acme_issuance_operation_snapshot_047()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    snapshot_tenant_id uuid;
    snapshot_scope_id uuid;
    snapshot_actor_id uuid;
    scope_tenant_id uuid;
BEGIN
    BEGIN
        snapshot_tenant_id := (NEW.request_snapshot ->> 'TenantID')::uuid;
        snapshot_scope_id := (NEW.request_snapshot ->> 'ScopeID')::uuid;
        snapshot_actor_id := (NEW.request_snapshot ->> 'ActorUserID')::uuid;
    EXCEPTION WHEN invalid_text_representation THEN
        RAISE EXCEPTION 'ACME issuance request snapshot identity is invalid' USING ERRCODE = 'P0001';
    END;

    SELECT scope.tenant_id INTO scope_tenant_id
    FROM access_scopes scope
    WHERE scope.id = NEW.tenant_scope_id AND scope.kind = 'tenant';
    IF NOT FOUND
       OR snapshot_tenant_id IS NULL
       OR snapshot_scope_id IS NULL
       OR snapshot_actor_id IS NULL
       OR snapshot_scope_id IS DISTINCT FROM NEW.tenant_scope_id
       OR snapshot_tenant_id IS DISTINCT FROM scope_tenant_id
       OR NOT EXISTS (
           SELECT 1
           FROM tenants tenant
           JOIN memberships membership
             ON membership.scope_id = NEW.tenant_scope_id
            AND membership.user_id = snapshot_actor_id
            AND membership.status = 'active'
           JOIN users account
             ON account.id = snapshot_actor_id
            AND account.status = 'active'
           WHERE tenant.id = scope_tenant_id AND tenant.status = 'active'
       ) THEN
        RAISE EXCEPTION 'ACME issuance request snapshot is not bound to an active tenant actor'
            USING ERRCODE = 'P0001';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION assert_acme_operation_has_initial_event()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM acme_issuance_operation_events
        WHERE tenant_scope_id = NEW.tenant_scope_id
          AND operation_id = NEW.operation_id
          AND revision = 1
          AND event_type = 'claim_created'
    ) THEN
        RAISE EXCEPTION 'ACME issuance operation requires an initial claim fact' USING ERRCODE = 'P0001';
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION assert_acme_challenge_has_intent()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM acme_issuance_challenge_events
        WHERE tenant_scope_id = NEW.tenant_scope_id
          AND operation_id = NEW.operation_id
          AND attempt_id = NEW.attempt_id
          AND revision = 1
          AND state = 'intent'
    ) THEN
        RAISE EXCEPTION 'ACME challenge attempt requires an initial cleanup intent' USING ERRCODE = 'P0001';
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION validate_acme_issuance_operation_event()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    previous acme_issuance_operation_events%ROWTYPE;
    same_external boolean;
    same_order boolean;
    same_certificate boolean;
    authorization_url text;
    expected_phase text;
    database_now timestamptz := statement_timestamp();
BEGIN
    PERFORM 1 FROM acme_issuance_operations
    WHERE tenant_scope_id = NEW.tenant_scope_id AND operation_id = NEW.operation_id
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'ACME issuance operation is missing' USING ERRCODE = 'P0001';
    END IF;
    IF NEW.occurred_at < database_now - interval '5 minutes'
       OR NEW.occurred_at > database_now + interval '1 minute' THEN
        RAISE EXCEPTION 'ACME issuance event time is outside the database clock allowance' USING ERRCODE = 'P0001';
    END IF;

    IF NEW.revision = 1 THEN
        IF NEW.event_type <> 'claim_created'
           OR NEW.phase <> 'claimed'
           OR NEW.status <> 'active'
           OR NEW.fence_token IS DISTINCT FROM NEW.lease_token
           OR NEW.lease_expires_at <= database_now
           OR NEW.order_intent_pending
           OR NEW.account_uri IS NOT NULL
           OR NEW.order_url IS NOT NULL
           OR NEW.finalize_url IS NOT NULL
           OR cardinality(NEW.authorization_urls) <> 0
           OR NEW.certificate_url IS NOT NULL
           OR NEW.certificate_spki_sha256 IS NOT NULL
           OR NEW.leaf_fingerprint_sha256 IS NOT NULL THEN
            RAISE EXCEPTION 'invalid initial ACME issuance claim event' USING ERRCODE = 'P0001';
        END IF;
        RETURN NEW;
    END IF;

    SELECT * INTO previous
    FROM acme_issuance_operation_events
    WHERE tenant_scope_id = NEW.tenant_scope_id
      AND operation_id = NEW.operation_id
      AND revision = NEW.revision - 1;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'ACME issuance event revision is not contiguous' USING ERRCODE = 'P0001';
    END IF;
    IF previous.status IN ('completed', 'failed') THEN
        RAISE EXCEPTION 'terminal ACME issuance operation cannot transition' USING ERRCODE = 'P0001';
    END IF;
    IF NEW.occurred_at < previous.occurred_at THEN
        RAISE EXCEPTION 'ACME issuance event time cannot move backwards' USING ERRCODE = 'P0001';
    END IF;

    same_order := ROW(NEW.order_url, NEW.finalize_url, NEW.authorization_urls)
        IS NOT DISTINCT FROM ROW(previous.order_url, previous.finalize_url, previous.authorization_urls);
    same_certificate := ROW(NEW.certificate_url, NEW.certificate_spki_sha256, NEW.leaf_fingerprint_sha256)
        IS NOT DISTINCT FROM ROW(previous.certificate_url, previous.certificate_spki_sha256, previous.leaf_fingerprint_sha256);
    same_external := NEW.account_uri IS NOT DISTINCT FROM previous.account_uri
        AND same_order AND same_certificate;

    IF NEW.event_type = 'lease_taken_over' THEN
        IF NOT (
            (previous.status = 'active' AND previous.lease_expires_at <= database_now)
            OR
            (previous.status = 'retry_wait' AND previous.next_reconcile_at <= database_now)
        )
        OR NEW.status <> 'active'
        OR NEW.fence_token IS DISTINCT FROM NEW.lease_token
        OR NEW.lease_expires_at <= database_now
        OR NEW.lease_token IS NOT DISTINCT FROM previous.lease_token
        OR NEW.phase <> previous.phase
        OR NEW.order_intent_pending IS DISTINCT FROM previous.order_intent_pending
        OR NOT same_external THEN
            RAISE EXCEPTION 'invalid ACME issuance lease takeover' USING ERRCODE = 'P0001';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.event_type IN ('retry_scheduled', 'failed', 'completed') THEN
        expected_phase := previous.phase;
        IF NEW.event_type = 'completed' THEN
            expected_phase := 'completed';
        END IF;
        IF previous.status <> 'active'
           OR previous.lease_expires_at <= database_now
           OR NEW.fence_token IS DISTINCT FROM previous.lease_token
           OR NEW.phase <> expected_phase
           OR NEW.order_intent_pending IS DISTINCT FROM previous.order_intent_pending
           OR NOT same_external THEN
            RAISE EXCEPTION 'invalid ACME issuance terminal or retry transition' USING ERRCODE = 'P0001';
        END IF;
        IF NEW.event_type = 'retry_scheduled' AND NEW.status <> 'retry_wait'
           OR NEW.event_type = 'failed' AND NEW.status <> 'failed'
           OR NEW.event_type = 'completed' AND (
               NEW.status <> 'completed' OR previous.phase <> 'certificate_saved'
           ) THEN
            RAISE EXCEPTION 'ACME issuance event type does not match terminal status' USING ERRCODE = 'P0001';
        END IF;
        RETURN NEW;
    END IF;

    IF previous.status <> 'active'
       OR NEW.status <> 'active'
       OR NEW.fence_token IS DISTINCT FROM NEW.lease_token
       OR NEW.lease_token IS DISTINCT FROM previous.lease_token
       OR NEW.lease_expires_at IS DISTINCT FROM previous.lease_expires_at
       OR previous.lease_expires_at <= database_now THEN
        RAISE EXCEPTION 'ACME issuance lease fence rejected the event' USING ERRCODE = 'P0001';
    END IF;

    CASE NEW.event_type
    WHEN 'account_registered' THEN
        IF previous.phase <> 'claimed' OR NEW.phase <> 'claimed'
           OR previous.account_uri IS NOT NULL OR NEW.account_uri IS NULL
           OR NEW.order_intent_pending
           OR NEW.order_intent_pending IS DISTINCT FROM previous.order_intent_pending
           OR NOT same_order OR NOT same_certificate THEN
            RAISE EXCEPTION 'invalid ACME account registration transition' USING ERRCODE = 'P0001';
        END IF;
    WHEN 'order_intent' THEN
        IF previous.phase <> 'claimed' OR NEW.phase <> 'claimed'
           OR previous.account_uri IS NULL
           OR previous.order_intent_pending OR NOT NEW.order_intent_pending
           OR NOT same_external THEN
            RAISE EXCEPTION 'invalid ACME order intent transition' USING ERRCODE = 'P0001';
        END IF;
    WHEN 'order_rejected' THEN
        IF previous.phase <> 'claimed' OR NEW.phase <> 'claimed'
           OR NOT previous.order_intent_pending OR NEW.order_intent_pending
           OR NOT same_external THEN
            RAISE EXCEPTION 'invalid ACME rejected order transition' USING ERRCODE = 'P0001';
        END IF;
    WHEN 'order_created' THEN
        IF previous.phase <> 'claimed' OR NEW.phase <> 'ordered'
           OR NOT previous.order_intent_pending OR NEW.order_intent_pending
           OR NEW.account_uri IS DISTINCT FROM previous.account_uri
           OR previous.order_url IS NOT NULL OR previous.finalize_url IS NOT NULL
           OR cardinality(previous.authorization_urls) <> 0
           OR NEW.order_url IS NULL OR NEW.finalize_url IS NULL
           OR NEW.account_uri IS NULL
           OR cardinality(NEW.authorization_urls) < 1
           OR NOT same_certificate THEN
            RAISE EXCEPTION 'invalid ACME order creation transition' USING ERRCODE = 'P0001';
        END IF;
        FOR authorization_url IN SELECT unnest(NEW.authorization_urls) LOOP
            IF authorization_url NOT LIKE 'https://%'
               OR octet_length(authorization_url) > 4096
               OR authorization_url ~ '[[:cntrl:]]' THEN
                RAISE EXCEPTION 'invalid ACME authorization URL' USING ERRCODE = 'P0001';
            END IF;
        END LOOP;
        IF (
            SELECT count(*) <> count(DISTINCT value)
            FROM unnest(NEW.authorization_urls) AS value
        ) THEN
            RAISE EXCEPTION 'duplicate ACME authorization URL' USING ERRCODE = 'P0001';
        END IF;
    WHEN 'authorizing' THEN
        IF previous.phase <> 'ordered' OR NEW.phase <> 'authorizing'
           OR NEW.order_intent_pending OR NOT same_external THEN
            RAISE EXCEPTION 'invalid ACME authorizing transition' USING ERRCODE = 'P0001';
        END IF;
    WHEN 'authorization_ready' THEN
        IF previous.phase <> 'authorizing' OR NEW.phase <> 'ready'
           OR NEW.order_intent_pending OR NOT same_external THEN
            RAISE EXCEPTION 'invalid ACME authorization-ready transition' USING ERRCODE = 'P0001';
        END IF;
    WHEN 'finalize_intent' THEN
        IF previous.phase <> 'ready' OR NEW.phase <> 'finalizing'
           OR NEW.order_intent_pending OR NOT same_external THEN
            RAISE EXCEPTION 'invalid ACME finalize intent transition' USING ERRCODE = 'P0001';
        END IF;
    WHEN 'certificate_saved' THEN
        IF previous.phase NOT IN ('finalizing', 'certificate_saved')
           OR NEW.phase <> 'certificate_saved'
           OR NEW.order_intent_pending
           OR NEW.account_uri IS DISTINCT FROM previous.account_uri
           OR NOT same_order
           OR NEW.certificate_url IS NULL
           OR NEW.certificate_spki_sha256 IS NULL
           OR NEW.leaf_fingerprint_sha256 IS NULL
           OR previous.certificate_url IS NOT NULL AND NOT same_certificate THEN
            RAISE EXCEPTION 'invalid ACME certificate save transition' USING ERRCODE = 'P0001';
        END IF;
    ELSE
        RAISE EXCEPTION 'ACME issuance event is not valid after the initial claim' USING ERRCODE = 'P0001';
    END CASE;
    RETURN NEW;
END;
$$;

CREATE FUNCTION validate_acme_challenge_attempt()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    operation_state acme_issuance_operation_events%ROWTYPE;
    expected_attempt integer;
    database_now timestamptz := statement_timestamp();
    frozen_request jsonb;
BEGIN
    SELECT request_snapshot INTO frozen_request FROM acme_issuance_operations
    WHERE tenant_scope_id = NEW.tenant_scope_id AND operation_id = NEW.operation_id
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'ACME issuance operation is missing' USING ERRCODE = 'P0001';
    END IF;
    SELECT * INTO operation_state
    FROM acme_issuance_operation_events
    WHERE tenant_scope_id = NEW.tenant_scope_id AND operation_id = NEW.operation_id
    ORDER BY revision DESC LIMIT 1;
    IF NEW.created_at < database_now - interval '5 minutes'
       OR NEW.created_at > database_now + interval '1 minute'
       OR operation_state.revision IS NULL
       OR operation_state.status <> 'active'
       OR operation_state.phase <> 'authorizing'
       OR operation_state.lease_expires_at <= database_now
       OR NOT NEW.authorization_url = ANY(operation_state.authorization_urls)
       OR NOT (
           (NOT NEW.wildcard AND (frozen_request -> 'Domains') ? NEW.identifier)
           OR
           (NEW.wildcard AND (frozen_request -> 'Domains') ? ('*.' || NEW.identifier))
       ) THEN
        RAISE EXCEPTION 'ACME challenge attempt is outside the active authorization lease' USING ERRCODE = 'P0001';
    END IF;
    SELECT COALESCE(max(attempt_number), 0) + 1 INTO expected_attempt
    FROM acme_issuance_challenge_attempts
    WHERE tenant_scope_id = NEW.tenant_scope_id
      AND operation_id = NEW.operation_id
      AND authorization_url = NEW.authorization_url;
    IF NEW.attempt_number <> expected_attempt THEN
        RAISE EXCEPTION 'ACME challenge attempt number is not contiguous' USING ERRCODE = 'P0001';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION validate_acme_challenge_event()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    operation_state acme_issuance_operation_events%ROWTYPE;
    previous acme_issuance_challenge_events%ROWTYPE;
    database_now timestamptz := statement_timestamp();
BEGIN
    PERFORM 1 FROM acme_issuance_operations
    WHERE tenant_scope_id = NEW.tenant_scope_id AND operation_id = NEW.operation_id
    FOR UPDATE;
    SELECT * INTO operation_state
    FROM acme_issuance_operation_events
    WHERE tenant_scope_id = NEW.tenant_scope_id AND operation_id = NEW.operation_id
    ORDER BY revision DESC LIMIT 1;
    IF NEW.occurred_at < database_now - interval '5 minutes'
       OR NEW.occurred_at > database_now + interval '1 minute'
       OR operation_state.revision IS NULL
       OR operation_state.status <> 'active'
       OR operation_state.phase <> 'authorizing'
       OR operation_state.lease_token IS DISTINCT FROM NEW.lease_token
       OR operation_state.lease_expires_at <= database_now THEN
        RAISE EXCEPTION 'ACME challenge lease fence rejected the event' USING ERRCODE = 'P0001';
    END IF;

    IF NEW.revision = 1 THEN
        IF NEW.state <> 'intent' THEN
            RAISE EXCEPTION 'ACME challenge attempt must start as intent' USING ERRCODE = 'P0001';
        END IF;
        RETURN NEW;
    END IF;
    SELECT * INTO previous
    FROM acme_issuance_challenge_events
    WHERE tenant_scope_id = NEW.tenant_scope_id
      AND operation_id = NEW.operation_id
      AND attempt_id = NEW.attempt_id
      AND revision = NEW.revision - 1;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'ACME challenge event revision is not contiguous' USING ERRCODE = 'P0001';
    END IF;
    IF NEW.occurred_at < previous.occurred_at
       OR previous.state = 'cleaned'
       OR NEW.state = 'intent'
       OR NEW.state = 'published' AND previous.state <> 'intent'
       OR NEW.state = 'published' AND NEW.lease_token IS DISTINCT FROM previous.lease_token
       OR NEW.state = 'cleanup_claimed' AND previous.state NOT IN ('intent', 'published', 'cleanup_claimed')
       OR NEW.state = 'cleaned' AND previous.state <> 'cleanup_claimed'
       OR NEW.state = 'cleaned' AND NEW.lease_token IS DISTINCT FROM previous.lease_token THEN
        RAISE EXCEPTION 'invalid ACME challenge state transition' USING ERRCODE = 'P0001';
    END IF;
    RETURN NEW;
END;
$$;

CREATE CONSTRAINT TRIGGER acme_issuance_operation_requires_claim
AFTER INSERT ON acme_issuance_operations
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION assert_acme_operation_has_initial_event();
CREATE TRIGGER acme_issuance_operation_snapshot_validate_047
BEFORE INSERT ON acme_issuance_operations
FOR EACH ROW EXECUTE FUNCTION validate_acme_issuance_operation_snapshot_047();
CREATE TRIGGER acme_issuance_operations_immutable
BEFORE UPDATE OR DELETE OR TRUNCATE ON acme_issuance_operations
FOR EACH STATEMENT EXECUTE FUNCTION protect_acme_issuance_facts();

CREATE TRIGGER acme_issuance_operation_events_validate
BEFORE INSERT ON acme_issuance_operation_events
FOR EACH ROW EXECUTE FUNCTION validate_acme_issuance_operation_event();
CREATE TRIGGER acme_issuance_operation_events_immutable
BEFORE UPDATE OR DELETE OR TRUNCATE ON acme_issuance_operation_events
FOR EACH STATEMENT EXECUTE FUNCTION protect_acme_issuance_facts();

CREATE CONSTRAINT TRIGGER acme_issuance_challenge_requires_intent
AFTER INSERT ON acme_issuance_challenge_attempts
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION assert_acme_challenge_has_intent();
CREATE TRIGGER acme_issuance_challenge_attempts_validate
BEFORE INSERT ON acme_issuance_challenge_attempts
FOR EACH ROW EXECUTE FUNCTION validate_acme_challenge_attempt();
CREATE TRIGGER acme_issuance_challenge_attempts_immutable
BEFORE UPDATE OR DELETE OR TRUNCATE ON acme_issuance_challenge_attempts
FOR EACH STATEMENT EXECUTE FUNCTION protect_acme_issuance_facts();
CREATE TRIGGER acme_issuance_challenge_events_validate
BEFORE INSERT ON acme_issuance_challenge_events
FOR EACH ROW EXECUTE FUNCTION validate_acme_challenge_event();
CREATE TRIGGER acme_issuance_challenge_events_immutable
BEFORE UPDATE OR DELETE OR TRUNCATE ON acme_issuance_challenge_events
FOR EACH STATEMENT EXECUTE FUNCTION protect_acme_issuance_facts();

ALTER TABLE acme_issuance_operations ENABLE ALWAYS TRIGGER acme_issuance_operation_requires_claim;
ALTER TABLE acme_issuance_operations ENABLE ALWAYS TRIGGER acme_issuance_operation_snapshot_validate_047;
ALTER TABLE acme_issuance_operations ENABLE ALWAYS TRIGGER acme_issuance_operations_immutable;
ALTER TABLE acme_issuance_operation_events ENABLE ALWAYS TRIGGER acme_issuance_operation_events_validate;
ALTER TABLE acme_issuance_operation_events ENABLE ALWAYS TRIGGER acme_issuance_operation_events_immutable;
ALTER TABLE acme_issuance_challenge_attempts ENABLE ALWAYS TRIGGER acme_issuance_challenge_requires_intent;
ALTER TABLE acme_issuance_challenge_attempts ENABLE ALWAYS TRIGGER acme_issuance_challenge_attempts_validate;
ALTER TABLE acme_issuance_challenge_attempts ENABLE ALWAYS TRIGGER acme_issuance_challenge_attempts_immutable;
ALTER TABLE acme_issuance_challenge_events ENABLE ALWAYS TRIGGER acme_issuance_challenge_events_validate;
ALTER TABLE acme_issuance_challenge_events ENABLE ALWAYS TRIGGER acme_issuance_challenge_events_immutable;
