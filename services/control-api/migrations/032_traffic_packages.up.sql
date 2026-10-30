CREATE TABLE traffic_package_product_snapshots (
    id uuid PRIMARY KEY,
    product_id uuid NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    audience text NOT NULL CHECK (audience IN ('global', 'tenant')),
    owner_tenant_scope_id uuid REFERENCES access_scopes(id) ON DELETE RESTRICT,
    name text NOT NULL CHECK (
        name = btrim(name) AND octet_length(name) BETWEEN 1 AND 128
        AND name !~ '[[:cntrl:]]'
    ),
    quota_bytes bigint NOT NULL CHECK (quota_bytes > 0),
    validity_days integer NOT NULL CHECK (validity_days BETWEEN 1 AND 3650),
    expiry_timezone text NOT NULL CHECK (
        expiry_timezone = 'UTC' OR (
            octet_length(expiry_timezone) BETWEEN 3 AND 128
            AND expiry_timezone <> 'Local'
            AND expiry_timezone ~ '^[A-Za-z][A-Za-z0-9._+-]*/[A-Za-z0-9][A-Za-z0-9._+/-]*$'
            AND position('..' IN expiry_timezone) = 0
        )
    ),
    priority integer NOT NULL CHECK (priority BETWEEN 0 AND 10000),
    currency text NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    price_minor bigint NOT NULL CHECK (price_minor >= 0),
    metering_scope text NOT NULL CHECK (
        octet_length(metering_scope) BETWEEN 1 AND 64
        AND metering_scope ~ '^[a-z][a-z0-9._-]*$'
    ),
    metering_version text NOT NULL CHECK (
        octet_length(metering_version) BETWEEN 1 AND 32
        AND metering_version ~ '^[A-Za-z0-9][A-Za-z0-9._-]*$'
    ),
    actor_user_id uuid NOT NULL,
    actor_scope_id uuid NOT NULL,
    idempotency_key text NOT NULL CHECK (
        octet_length(idempotency_key) BETWEEN 1 AND 128
        AND idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    request_id text NOT NULL CHECK (
        octet_length(request_id) BETWEEN 1 AND 128
        AND request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    trace_id text NOT NULL CHECK (
        octet_length(trace_id) BETWEEN 1 AND 128
        AND trace_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    created_at timestamptz NOT NULL,
    UNIQUE (product_id, revision),
    UNIQUE (actor_user_id, idempotency_key),
    FOREIGN KEY (actor_scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    CHECK (
        (audience = 'global' AND owner_tenant_scope_id IS NULL) OR
        (audience = 'tenant' AND owner_tenant_scope_id IS NOT NULL)
    )
);

CREATE INDEX traffic_package_product_snapshots_owner_idx
    ON traffic_package_product_snapshots (owner_tenant_scope_id, created_at DESC)
    WHERE owner_tenant_scope_id IS NOT NULL;
CREATE INDEX traffic_package_product_snapshots_actor_idx
    ON traffic_package_product_snapshots (actor_scope_id, actor_user_id);

CREATE TABLE traffic_package_buckets (
    id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    currency text NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    metering_scope text NOT NULL CHECK (
        octet_length(metering_scope) BETWEEN 1 AND 64
        AND metering_scope ~ '^[a-z][a-z0-9._-]*$'
    ),
    metering_version text NOT NULL CHECK (
        octet_length(metering_version) BETWEEN 1 AND 32
        AND metering_version ~ '^[A-Za-z0-9][A-Za-z0-9._-]*$'
    ),
    created_at timestamptz NOT NULL,
    UNIQUE (tenant_scope_id, currency, metering_scope, metering_version),
    UNIQUE (tenant_scope_id, currency, metering_scope, metering_version, id)
);

CREATE TABLE traffic_package_grants (
    id uuid PRIMARY KEY,
    bucket_id uuid NOT NULL,
    tenant_scope_id uuid NOT NULL,
    currency text NOT NULL,
    metering_scope text NOT NULL,
    metering_version text NOT NULL,
    product_snapshot_id uuid NOT NULL REFERENCES traffic_package_product_snapshots(id) ON DELETE RESTRICT,
    product_snapshot jsonb NOT NULL CHECK (
        jsonb_typeof(product_snapshot) = 'object'
        AND octet_length(product_snapshot::text) <= 4096
    ),
    granted_bytes bigint NOT NULL CHECK (granted_bytes > 0),
    remaining_bytes bigint NOT NULL CHECK (remaining_bytes BETWEEN 0 AND granted_bytes),
    starts_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    expiry_timezone text NOT NULL,
    priority integer NOT NULL CHECK (priority BETWEEN 0 AND 10000),
    price_minor bigint NOT NULL CHECK (price_minor >= 0),
    external_ledger_reference text CHECK (
        external_ledger_reference IS NULL OR external_ledger_reference ~
        '^billing:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    ),
    status text NOT NULL CHECK (status IN ('active', 'exhausted', 'expired', 'reversed')),
    revision bigint NOT NULL CHECK (revision > 0),
    created_by_user_id uuid NOT NULL,
    created_by_scope_id uuid NOT NULL,
    request_id text NOT NULL CHECK (
        octet_length(request_id) BETWEEN 1 AND 128
        AND request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    trace_id text NOT NULL CHECK (
        octet_length(trace_id) BETWEEN 1 AND 128
        AND trace_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    FOREIGN KEY (tenant_scope_id, currency, metering_scope, metering_version, bucket_id)
        REFERENCES traffic_package_buckets(tenant_scope_id, currency, metering_scope, metering_version, id)
        ON DELETE RESTRICT,
    FOREIGN KEY (created_by_scope_id, created_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    UNIQUE (tenant_scope_id, currency, metering_scope, metering_version, id),
    CHECK (expires_at > starts_at),
    CHECK (price_minor = 0 OR external_ledger_reference IS NOT NULL),
    CHECK ((status = 'active') = (remaining_bytes > 0 AND status NOT IN ('expired', 'reversed'))),
    CHECK (status <> 'exhausted' OR remaining_bytes = 0),
    CHECK (status <> 'reversed' OR remaining_bytes = 0),
    CHECK (updated_at >= created_at)
);

CREATE INDEX traffic_package_grants_consume_idx
    ON traffic_package_grants (
        tenant_scope_id, currency, metering_scope, metering_version,
        status, priority, expires_at, starts_at, id
    );
CREATE INDEX traffic_package_grants_product_idx
    ON traffic_package_grants (product_snapshot_id);
CREATE INDEX traffic_package_grants_creator_idx
    ON traffic_package_grants (created_by_scope_id, created_by_user_id);

CREATE TABLE traffic_package_events (
    id uuid PRIMARY KEY,
    bucket_id uuid NOT NULL,
    tenant_scope_id uuid NOT NULL,
    currency text NOT NULL,
    metering_scope text NOT NULL,
    metering_version text NOT NULL,
    operation text NOT NULL CHECK (operation IN ('grant', 'consume', 'refund', 'expire', 'reverse')),
    source_event_key text CHECK (
        source_event_key IS NULL OR (
            octet_length(source_event_key) BETWEEN 1 AND 128
            AND source_event_key ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
        )
    ),
    related_event_id uuid REFERENCES traffic_package_events(id) ON DELETE RESTRICT,
    requested_bytes bigint NOT NULL CHECK (requested_bytes >= 0),
    actor_user_id uuid NOT NULL,
    actor_scope_id uuid NOT NULL,
    idempotency_key text NOT NULL CHECK (
        octet_length(idempotency_key) BETWEEN 1 AND 128
        AND idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    request_id text NOT NULL CHECK (
        octet_length(request_id) BETWEEN 1 AND 128
        AND request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    trace_id text NOT NULL CHECK (
        octet_length(trace_id) BETWEEN 1 AND 128
        AND trace_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    created_at timestamptz NOT NULL,
    FOREIGN KEY (tenant_scope_id, currency, metering_scope, metering_version, bucket_id)
        REFERENCES traffic_package_buckets(tenant_scope_id, currency, metering_scope, metering_version, id)
        ON DELETE RESTRICT,
    FOREIGN KEY (actor_scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    UNIQUE (tenant_scope_id, currency, metering_scope, metering_version, id),
    UNIQUE (tenant_scope_id, currency, metering_scope, metering_version, operation, idempotency_key),
    CHECK (
        (operation = 'consume' AND source_event_key IS NOT NULL AND related_event_id IS NULL AND requested_bytes > 0) OR
        (operation = 'refund' AND source_event_key IS NULL AND related_event_id IS NOT NULL AND requested_bytes > 0) OR
        (operation = 'grant' AND source_event_key IS NULL AND related_event_id IS NULL AND requested_bytes > 0) OR
        (operation = 'reverse' AND source_event_key IS NULL AND related_event_id IS NOT NULL AND requested_bytes > 0) OR
        (operation = 'expire' AND source_event_key IS NULL AND related_event_id IS NOT NULL AND requested_bytes = 0)
    )
);

CREATE UNIQUE INDEX traffic_package_events_source_once_idx
    ON traffic_package_events (
        tenant_scope_id, currency, metering_scope, metering_version, source_event_key
    ) WHERE operation = 'consume';
CREATE INDEX traffic_package_events_related_idx
    ON traffic_package_events (related_event_id) WHERE related_event_id IS NOT NULL;
CREATE INDEX traffic_package_events_actor_idx
    ON traffic_package_events (actor_scope_id, actor_user_id);
CREATE INDEX traffic_package_events_bucket_created_idx
    ON traffic_package_events (bucket_id, created_at DESC, id DESC);

CREATE TABLE traffic_package_ledger_entries (
    id uuid PRIMARY KEY,
    bucket_id uuid NOT NULL,
    tenant_scope_id uuid NOT NULL,
    currency text NOT NULL,
    metering_scope text NOT NULL,
    metering_version text NOT NULL,
    event_id uuid NOT NULL,
    grant_id uuid NOT NULL,
    allocation_order integer NOT NULL CHECK (allocation_order >= 0),
    side text NOT NULL CHECK (side IN ('credit', 'debit', 'memo')),
    amount_bytes bigint NOT NULL CHECK (
        (side IN ('credit', 'debit') AND amount_bytes > 0) OR
        (side = 'memo' AND amount_bytes = 0)
    ),
    grant_revision bigint NOT NULL CHECK (grant_revision > 0),
    remaining_after_bytes bigint NOT NULL CHECK (remaining_after_bytes >= 0),
    created_at timestamptz NOT NULL,
    FOREIGN KEY (tenant_scope_id, currency, metering_scope, metering_version, event_id)
        REFERENCES traffic_package_events(tenant_scope_id, currency, metering_scope, metering_version, id)
        ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, currency, metering_scope, metering_version, grant_id)
        REFERENCES traffic_package_grants(tenant_scope_id, currency, metering_scope, metering_version, id)
        ON DELETE RESTRICT,
    UNIQUE (event_id, grant_id),
    UNIQUE (event_id, allocation_order),
    UNIQUE (grant_id, grant_revision)
);

CREATE INDEX traffic_package_ledger_entries_grant_idx
    ON traffic_package_ledger_entries (grant_id, grant_revision DESC);

CREATE FUNCTION assert_traffic_package_tenant_scope()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    target_scope_id uuid;
    actual_kind text;
BEGIN
    IF TG_TABLE_NAME = 'traffic_package_product_snapshots' THEN
        target_scope_id := NEW.owner_tenant_scope_id;
        IF target_scope_id IS NULL THEN
            RETURN NEW;
        END IF;
    ELSE
        target_scope_id := NEW.tenant_scope_id;
    END IF;
    SELECT kind INTO actual_kind FROM access_scopes WHERE id = target_scope_id;
    IF actual_kind IS DISTINCT FROM 'tenant' THEN
        RAISE EXCEPTION 'traffic package scope must be a tenant scope';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER traffic_package_product_snapshots_scope_kind
BEFORE INSERT OR UPDATE OF owner_tenant_scope_id ON traffic_package_product_snapshots
FOR EACH ROW EXECUTE FUNCTION assert_traffic_package_tenant_scope();
CREATE TRIGGER traffic_package_buckets_scope_kind
BEFORE INSERT OR UPDATE OF tenant_scope_id ON traffic_package_buckets
FOR EACH ROW EXECUTE FUNCTION assert_traffic_package_tenant_scope();

CREATE FUNCTION prevent_traffic_package_append_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME;
END;
$$;

CREATE TRIGGER traffic_package_product_snapshots_append_only
BEFORE UPDATE OR DELETE ON traffic_package_product_snapshots
FOR EACH ROW EXECUTE FUNCTION prevent_traffic_package_append_mutation();
CREATE TRIGGER traffic_package_product_snapshots_no_truncate
BEFORE TRUNCATE ON traffic_package_product_snapshots
FOR EACH STATEMENT EXECUTE FUNCTION prevent_traffic_package_append_mutation();
CREATE TRIGGER traffic_package_buckets_append_only
BEFORE UPDATE OR DELETE ON traffic_package_buckets
FOR EACH ROW EXECUTE FUNCTION prevent_traffic_package_append_mutation();
CREATE TRIGGER traffic_package_buckets_no_truncate
BEFORE TRUNCATE ON traffic_package_buckets
FOR EACH STATEMENT EXECUTE FUNCTION prevent_traffic_package_append_mutation();
CREATE TRIGGER traffic_package_events_append_only
BEFORE UPDATE OR DELETE ON traffic_package_events
FOR EACH ROW EXECUTE FUNCTION prevent_traffic_package_append_mutation();
CREATE TRIGGER traffic_package_events_no_truncate
BEFORE TRUNCATE ON traffic_package_events
FOR EACH STATEMENT EXECUTE FUNCTION prevent_traffic_package_append_mutation();
CREATE TRIGGER traffic_package_ledger_entries_append_only
BEFORE UPDATE OR DELETE ON traffic_package_ledger_entries
FOR EACH ROW EXECUTE FUNCTION prevent_traffic_package_append_mutation();
CREATE TRIGGER traffic_package_ledger_entries_no_truncate
BEFORE TRUNCATE ON traffic_package_ledger_entries
FOR EACH STATEMENT EXECUTE FUNCTION prevent_traffic_package_append_mutation();

CREATE FUNCTION protect_traffic_package_grant()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
        RAISE EXCEPTION 'traffic package grants cannot be deleted';
    END IF;
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.bucket_id IS DISTINCT FROM OLD.bucket_id
       OR NEW.tenant_scope_id IS DISTINCT FROM OLD.tenant_scope_id
       OR NEW.currency IS DISTINCT FROM OLD.currency
       OR NEW.metering_scope IS DISTINCT FROM OLD.metering_scope
       OR NEW.metering_version IS DISTINCT FROM OLD.metering_version
       OR NEW.product_snapshot_id IS DISTINCT FROM OLD.product_snapshot_id
       OR NEW.product_snapshot IS DISTINCT FROM OLD.product_snapshot
       OR NEW.granted_bytes IS DISTINCT FROM OLD.granted_bytes
       OR NEW.starts_at IS DISTINCT FROM OLD.starts_at
       OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
       OR NEW.expiry_timezone IS DISTINCT FROM OLD.expiry_timezone
       OR NEW.priority IS DISTINCT FROM OLD.priority
       OR NEW.price_minor IS DISTINCT FROM OLD.price_minor
       OR NEW.external_ledger_reference IS DISTINCT FROM OLD.external_ledger_reference
       OR NEW.created_by_user_id IS DISTINCT FROM OLD.created_by_user_id
       OR NEW.created_by_scope_id IS DISTINCT FROM OLD.created_by_scope_id
       OR NEW.request_id IS DISTINCT FROM OLD.request_id
       OR NEW.trace_id IS DISTINCT FROM OLD.trace_id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'traffic package grant snapshot is immutable';
    END IF;
    IF NEW.revision <> OLD.revision + 1 THEN
        RAISE EXCEPTION 'traffic package grant revision must advance by one';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER traffic_package_grants_protect
BEFORE UPDATE OR DELETE ON traffic_package_grants
FOR EACH ROW EXECUTE FUNCTION protect_traffic_package_grant();
CREATE TRIGGER traffic_package_grants_no_truncate
BEFORE TRUNCATE ON traffic_package_grants
FOR EACH STATEMENT EXECUTE FUNCTION protect_traffic_package_grant();

CREATE FUNCTION assert_traffic_package_event_balanced()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    target_event_id uuid;
    target_operation text;
    target_requested bigint;
    target_related uuid;
    entry_count bigint;
    credit_total numeric;
    debit_total numeric;
    memo_count bigint;
    original_operation text;
    original_requested bigint;
    refunded_total numeric;
    invalid_grant_refund boolean;
    matching_entries bigint;
BEGIN
    IF TG_TABLE_NAME = 'traffic_package_events' THEN
        target_event_id := NEW.id;
    ELSE
        target_event_id := NEW.event_id;
    END IF;
    SELECT operation, requested_bytes, related_event_id
    INTO target_operation, target_requested, target_related
    FROM traffic_package_events WHERE id = target_event_id;
    IF target_operation IS NULL THEN
        RETURN NULL;
    END IF;

    SELECT count(*),
           COALESCE(sum(amount_bytes::numeric) FILTER (WHERE side = 'credit'), 0),
           COALESCE(sum(amount_bytes::numeric) FILTER (WHERE side = 'debit'), 0),
           count(*) FILTER (WHERE side = 'memo')
    INTO entry_count, credit_total, debit_total, memo_count
    FROM traffic_package_ledger_entries WHERE event_id = target_event_id;

    IF (target_operation = 'grant' AND (entry_count <> 1 OR credit_total <> target_requested OR debit_total <> 0))
       OR (target_operation = 'consume' AND (entry_count < 1 OR debit_total <> target_requested OR credit_total <> 0))
       OR (target_operation = 'refund' AND (entry_count < 1 OR credit_total <> target_requested OR debit_total <> 0))
       OR (target_operation = 'reverse' AND (entry_count <> 1 OR debit_total <> target_requested OR credit_total <> 0))
       OR (target_operation = 'expire' AND (entry_count <> 1 OR memo_count <> 1)) THEN
        RAISE EXCEPTION 'traffic package event % has invalid ledger entries', target_event_id;
    END IF;

    IF target_operation = 'refund' THEN
        SELECT operation, requested_bytes INTO original_operation, original_requested
        FROM traffic_package_events original
        WHERE original.id = target_related
          AND (original.tenant_scope_id, original.currency, original.metering_scope, original.metering_version) =
              (SELECT tenant_scope_id, currency, metering_scope, metering_version
               FROM traffic_package_events WHERE id = target_event_id);
        IF original_operation IS DISTINCT FROM 'consume' THEN
            RAISE EXCEPTION 'traffic package refund % has invalid original event', target_event_id;
        END IF;
        SELECT COALESCE(sum(requested_bytes::numeric), 0) INTO refunded_total
        FROM traffic_package_events
        WHERE operation = 'refund' AND related_event_id = target_related;
        IF refunded_total > original_requested THEN
            RAISE EXCEPTION 'traffic package refund % exceeds original event', target_event_id;
        END IF;
        SELECT EXISTS (
            SELECT 1
            FROM traffic_package_ledger_entries refund_entry
            WHERE refund_entry.event_id = target_event_id
              AND (
                  NOT EXISTS (
                      SELECT 1 FROM traffic_package_ledger_entries original_entry
                      WHERE original_entry.event_id = target_related
                        AND original_entry.grant_id = refund_entry.grant_id
                  ) OR refund_entry.amount_bytes::numeric >
                      (SELECT original_entry.amount_bytes::numeric - COALESCE(sum(prior.amount_bytes::numeric), 0)
                       FROM traffic_package_ledger_entries original_entry
                       LEFT JOIN traffic_package_events prior_event
                         ON prior_event.related_event_id = target_related
                        AND prior_event.operation = 'refund'
                        AND prior_event.id <> target_event_id
                       LEFT JOIN traffic_package_ledger_entries prior
                         ON prior.event_id = prior_event.id
                        AND prior.grant_id = original_entry.grant_id
                       WHERE original_entry.event_id = target_related
                         AND original_entry.grant_id = refund_entry.grant_id
                       GROUP BY original_entry.amount_bytes)
              )
        ) INTO invalid_grant_refund;
        IF invalid_grant_refund THEN
            RAISE EXCEPTION 'traffic package refund % exceeds original grant allocation', target_event_id;
        END IF;
    ELSIF target_operation IN ('expire', 'reverse') THEN
        SELECT operation, requested_bytes INTO original_operation, original_requested
        FROM traffic_package_events original
        WHERE original.id = target_related
          AND (original.tenant_scope_id, original.currency, original.metering_scope, original.metering_version) =
              (SELECT tenant_scope_id, currency, metering_scope, metering_version
               FROM traffic_package_events WHERE id = target_event_id);
        SELECT count(*) INTO matching_entries
        FROM traffic_package_ledger_entries original_entry
        JOIN traffic_package_ledger_entries target_entry
          ON target_entry.event_id = target_event_id
         AND target_entry.grant_id = original_entry.grant_id
        WHERE original_entry.event_id = target_related;
        IF original_operation IS DISTINCT FROM 'grant' OR matching_entries <> 1
           OR (target_operation = 'reverse' AND target_requested <> original_requested) THEN
            RAISE EXCEPTION 'traffic package event % has invalid grant relation', target_event_id;
        END IF;
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER traffic_package_events_balanced
AFTER INSERT ON traffic_package_events
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION assert_traffic_package_event_balanced();
CREATE CONSTRAINT TRIGGER traffic_package_ledger_entries_balanced
AFTER INSERT ON traffic_package_ledger_entries
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION assert_traffic_package_event_balanced();

CREATE FUNCTION assert_traffic_package_grant_reconciled()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    target_grant_id uuid;
    cached_remaining bigint;
    cached_revision bigint;
    cached_status text;
    entry_count bigint;
    maximum_revision bigint;
    recomputed_remaining numeric;
    invalid_history boolean;
BEGIN
    IF TG_TABLE_NAME = 'traffic_package_grants' THEN
        target_grant_id := NEW.id;
    ELSE
        target_grant_id := NEW.grant_id;
    END IF;
    SELECT remaining_bytes, revision, status
    INTO cached_remaining, cached_revision, cached_status
    FROM traffic_package_grants WHERE id = target_grant_id;
    IF cached_remaining IS NULL THEN
        RETURN NULL;
    END IF;

    SELECT count(*), COALESCE(max(grant_revision), 0),
           COALESCE(sum(CASE side WHEN 'credit' THEN amount_bytes::numeric
                                  WHEN 'debit' THEN -amount_bytes::numeric ELSE 0 END), 0)
    INTO entry_count, maximum_revision, recomputed_remaining
    FROM traffic_package_ledger_entries WHERE grant_id = target_grant_id;
    SELECT COALESCE(bool_or(remaining_after_bytes::numeric <> running_remaining), false)
    INTO invalid_history
    FROM (
        SELECT remaining_after_bytes,
               sum(CASE side WHEN 'credit' THEN amount_bytes::numeric
                             WHEN 'debit' THEN -amount_bytes::numeric ELSE 0 END)
                   OVER (ORDER BY grant_revision) AS running_remaining
        FROM traffic_package_ledger_entries WHERE grant_id = target_grant_id
    ) history;

    IF cached_remaining::numeric <> recomputed_remaining
       OR cached_revision <> entry_count
       OR maximum_revision <> entry_count
       OR invalid_history
       OR (cached_status = 'active' AND cached_remaining = 0)
       OR (cached_status IN ('exhausted', 'reversed') AND cached_remaining <> 0) THEN
        RAISE EXCEPTION 'traffic package grant % snapshot does not match ledger', target_grant_id;
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER traffic_package_grants_reconciled
AFTER INSERT OR UPDATE ON traffic_package_grants
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION assert_traffic_package_grant_reconciled();
CREATE CONSTRAINT TRIGGER traffic_package_ledger_entries_reconciled
AFTER INSERT ON traffic_package_ledger_entries
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION assert_traffic_package_grant_reconciled();
