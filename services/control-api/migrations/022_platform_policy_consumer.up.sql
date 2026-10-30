CREATE TABLE platform_policy_deliveries (
    target_revision_id uuid PRIMARY KEY,
    scope_kind text NOT NULL CHECK (scope_kind IN ('global', 'installation')),
    installation_id uuid,
    scope_revision bigint NOT NULL CHECK (scope_revision BETWEEN 1 AND 9007199254740991),
    action text NOT NULL CHECK (action IN ('apply', 'withdraw')),
    schema_version text NOT NULL CHECK (schema_version = 'platform-policy/v1'),
    key_id text NOT NULL CHECK (
        char_length(key_id) BETWEEN 1 AND 128 AND
        key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    canonical_policy_sha256 bytea NOT NULL CHECK (octet_length(canonical_policy_sha256) = 32),
    canonical_policy bytea NOT NULL CHECK (octet_length(canonical_policy) BETWEEN 4 AND 65536),
    canonical_envelope bytea NOT NULL CHECK (octet_length(canonical_envelope) BETWEEN 1 AND 65536),
    signed_target bytea NOT NULL CHECK (octet_length(signed_target) BETWEEN 1 AND 131072),
    signed_target_sha256 bytea NOT NULL CHECK (octet_length(signed_target_sha256) = 32),
    signature bytea NOT NULL CHECK (octet_length(signature) = 64),
    signed_at timestamptz NOT NULL,
    valid_from timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    control_protocol_min integer NOT NULL CHECK (control_protocol_min > 0),
    control_protocol_max integer NOT NULL CHECK (control_protocol_max >= control_protocol_min),
    supersedes uuid,
    rollback_of uuid,
    fetched_at timestamptz NOT NULL,
    CHECK (expires_at > valid_from),
    CHECK (
        (scope_kind = 'global' AND installation_id IS NULL) OR
        (scope_kind = 'installation' AND installation_id IS NOT NULL)
    ),
    CHECK (
        (scope_revision = 1 AND supersedes IS NULL) OR
        (scope_revision > 1 AND supersedes IS NOT NULL)
    ),
    CHECK (rollback_of IS NULL OR action = 'apply')
);

CREATE UNIQUE INDEX platform_policy_deliveries_scope_revision_idx
    ON platform_policy_deliveries (
        scope_kind,
        COALESCE(installation_id, '00000000-0000-0000-0000-000000000000'::uuid),
        scope_revision
    );
CREATE INDEX platform_policy_deliveries_fetched_idx
    ON platform_policy_deliveries (fetched_at DESC, target_revision_id DESC);

CREATE TABLE platform_policy_ack_events (
    sequence bigint GENERATED ALWAYS AS IDENTITY UNIQUE,
    id uuid PRIMARY KEY,
    target_revision_id uuid NOT NULL REFERENCES platform_policy_deliveries(target_revision_id) ON DELETE RESTRICT,
    installation_id uuid NOT NULL,
    status text NOT NULL CHECK (status IN ('fetched', 'validated', 'applied', 'rejected', 'rolled_back')),
    error_code text CHECK (
        error_code IS NULL OR (
            char_length(error_code) BETWEEN 1 AND 96 AND
            error_code ~ '^[a-z][a-z0-9._-]*$'
        )
    ),
    observed_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    UNIQUE (target_revision_id, status),
    CHECK ((status = 'rejected' AND error_code IS NOT NULL) OR
           (status <> 'rejected' AND error_code IS NULL))
);

CREATE INDEX platform_policy_ack_events_target_idx
    ON platform_policy_ack_events (target_revision_id, sequence);

CREATE TABLE platform_policy_ack_outbox (
    ack_event_id uuid PRIMARY KEY REFERENCES platform_policy_ack_events(id) ON DELETE RESTRICT,
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at timestamptz NOT NULL,
    delivered_at timestamptz,
    last_error_code text CHECK (
        last_error_code IS NULL OR char_length(last_error_code) BETWEEN 1 AND 96
    ),
    updated_at timestamptz NOT NULL
);

CREATE INDEX platform_policy_ack_outbox_pending_idx
    ON platform_policy_ack_outbox (next_attempt_at, ack_event_id)
    WHERE delivered_at IS NULL;

CREATE TABLE platform_policy_scope_state (
    scope_key text PRIMARY KEY CHECK (
        scope_key = 'global' OR scope_key ~ '^installation:[0-9a-f-]{36}$'
    ),
    scope_kind text NOT NULL CHECK (scope_kind IN ('global', 'installation')),
    installation_id uuid,
    highwater_revision bigint NOT NULL CHECK (highwater_revision BETWEEN 1 AND 9007199254740991),
    head_target_revision_id uuid NOT NULL REFERENCES platform_policy_deliveries(target_revision_id) ON DELETE RESTRICT,
    lkg_target_revision_id uuid REFERENCES platform_policy_deliveries(target_revision_id) ON DELETE RESTRICT,
    active_target_revision_id uuid REFERENCES platform_policy_deliveries(target_revision_id) ON DELETE RESTRICT,
    updated_at timestamptz NOT NULL,
    CHECK (
        (scope_kind = 'global' AND scope_key = 'global' AND installation_id IS NULL) OR
        (scope_kind = 'installation' AND scope_key = 'installation:' || installation_id::text AND installation_id IS NOT NULL)
    )
);

CREATE TABLE platform_policy_sync_state (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    cursor text CHECK (cursor IS NULL OR octet_length(cursor) <= 512),
    etag text CHECK (etag IS NULL OR octet_length(etag) <= 128),
    resolved_at timestamptz,
    updated_at timestamptz NOT NULL
);

CREATE TABLE platform_policy_application_events (
    sequence bigint GENERATED ALWAYS AS IDENTITY UNIQUE,
    id uuid PRIMARY KEY,
    target_revision_id uuid NOT NULL REFERENCES platform_policy_deliveries(target_revision_id) ON DELETE RESTRICT,
    previous_effective_target_id uuid REFERENCES platform_policy_deliveries(target_revision_id) ON DELETE RESTRICT,
    effective_target_id uuid REFERENCES platform_policy_deliveries(target_revision_id) ON DELETE RESTRICT,
    action text NOT NULL CHECK (action IN ('apply', 'withdraw')),
    occurred_at timestamptz NOT NULL
);

CREATE FUNCTION reject_platform_policy_history_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'platform policy history is append-only';
END;
$$;

CREATE TRIGGER platform_policy_deliveries_immutable
BEFORE UPDATE OR DELETE ON platform_policy_deliveries
FOR EACH ROW EXECUTE FUNCTION reject_platform_policy_history_mutation();

CREATE TRIGGER platform_policy_deliveries_truncate_immutable
BEFORE TRUNCATE ON platform_policy_deliveries
FOR EACH STATEMENT EXECUTE FUNCTION reject_platform_policy_history_mutation();

CREATE TRIGGER platform_policy_ack_events_immutable
BEFORE UPDATE OR DELETE ON platform_policy_ack_events
FOR EACH ROW EXECUTE FUNCTION reject_platform_policy_history_mutation();

CREATE TRIGGER platform_policy_ack_events_truncate_immutable
BEFORE TRUNCATE ON platform_policy_ack_events
FOR EACH STATEMENT EXECUTE FUNCTION reject_platform_policy_history_mutation();

CREATE TRIGGER platform_policy_application_events_immutable
BEFORE UPDATE OR DELETE ON platform_policy_application_events
FOR EACH ROW EXECUTE FUNCTION reject_platform_policy_history_mutation();

CREATE TRIGGER platform_policy_application_events_truncate_immutable
BEFORE TRUNCATE ON platform_policy_application_events
FOR EACH STATEMENT EXECUTE FUNCTION reject_platform_policy_history_mutation();
