CREATE TABLE package_orders (
    id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    user_id uuid NOT NULL,
    operation text NOT NULL CHECK (operation IN (
        'purchase', 'renew', 'upgrade', 'downgrade', 'traffic_package_purchase'
    )),
    original_order_id uuid REFERENCES package_orders(id) ON DELETE RESTRICT,
    subscription_id uuid REFERENCES package_subscriptions(id) ON DELETE RESTRICT,
    product_kind text NOT NULL CHECK (product_kind IN ('package_subscription', 'traffic_package')),
    product_id uuid NOT NULL,
    product_revision bigint NOT NULL CHECK (product_revision > 0),
    traffic_product_snapshot_id uuid REFERENCES traffic_package_product_snapshots(id) ON DELETE RESTRICT,
    package_period text CHECK (package_period IS NULL OR package_period IN ('month', 'quarter', 'year')),
    product_snapshot jsonb NOT NULL CHECK (
        jsonb_typeof(product_snapshot) = 'object' AND octet_length(product_snapshot::text) <= 65536
    ),
    entitlement_snapshot jsonb CHECK (
        entitlement_snapshot IS NULL OR (
            jsonb_typeof(entitlement_snapshot) = 'object'
            AND octet_length(entitlement_snapshot::text) <= 65536
        )
    ),
    pricing_snapshot jsonb NOT NULL CHECK (
        jsonb_typeof(pricing_snapshot) = 'object' AND octet_length(pricing_snapshot::text) <= 16384
    ),
    currency text NOT NULL CHECK (currency = 'CNY'),
    original_amount_minor bigint NOT NULL CHECK (original_amount_minor >= 0),
    discount_amount_minor bigint NOT NULL CHECK (discount_amount_minor >= 0),
    payable_amount_minor bigint NOT NULL CHECK (payable_amount_minor >= 0),
    settlement_direction text NOT NULL CHECK (settlement_direction IN ('debit', 'credit', 'hold')),
    funding_source text NOT NULL CHECK (funding_source IN ('balance', 'provider')),
    effective_mode text NOT NULL CHECK (effective_mode IN ('immediate', 'next_cycle')),
    effective_at timestamptz NOT NULL,
    promotion_quote_id uuid REFERENCES promotion_quotes(id) ON DELETE RESTRICT,
    promotion_reservation_id uuid REFERENCES promotion_reservations(id) ON DELETE RESTRICT,
    request_id text NOT NULL CHECK (
        octet_length(request_id) BETWEEN 1 AND 128
        AND request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    trace_id text NOT NULL CHECK (
        octet_length(trace_id) BETWEEN 1 AND 128
        AND trace_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    created_by_scope_id uuid NOT NULL,
    created_by_user_id uuid NOT NULL,
    created_at timestamptz NOT NULL,
    FOREIGN KEY (tenant_scope_id, user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY (created_by_scope_id, created_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    CHECK (payable_amount_minor = original_amount_minor - discount_amount_minor),
    CHECK ((promotion_quote_id IS NULL) = (promotion_reservation_id IS NULL)),
    CHECK (
        (product_kind = 'package_subscription'
            AND traffic_product_snapshot_id IS NULL
            AND package_period IS NOT NULL
            AND entitlement_snapshot IS NOT NULL)
        OR
        (product_kind = 'traffic_package'
            AND traffic_product_snapshot_id IS NOT NULL
            AND package_period IS NULL
            AND entitlement_snapshot IS NULL)
    ),
    CHECK (
        (operation IN ('purchase', 'traffic_package_purchase') AND subscription_id IS NULL)
        OR (operation IN ('renew', 'upgrade', 'downgrade') AND subscription_id IS NOT NULL)
    ),
    CHECK (
        (operation IN ('upgrade', 'downgrade') AND effective_mode IN ('immediate', 'next_cycle'))
        OR (operation NOT IN ('upgrade', 'downgrade') AND effective_mode = 'immediate')
    ),
    CHECK (funding_source = 'balance' OR settlement_direction = 'debit')
);

CREATE INDEX package_orders_tenant_created_idx
    ON package_orders (tenant_scope_id, created_at DESC, id DESC);
CREATE INDEX package_orders_subscription_idx
    ON package_orders (subscription_id, created_at DESC) WHERE subscription_id IS NOT NULL;
CREATE INDEX package_orders_promotion_idx
    ON package_orders (promotion_reservation_id) WHERE promotion_reservation_id IS NOT NULL;

CREATE TABLE package_order_events (
    id uuid PRIMARY KEY,
    order_id uuid NOT NULL REFERENCES package_orders(id) ON DELETE RESTRICT,
    revision bigint NOT NULL CHECK (revision > 0),
    event_type text NOT NULL CHECK (event_type IN (
        'created', 'paid', 'fulfilled', 'cancelled', 'refund_applied', 'void_applied', 'failed'
    )),
    payload jsonb NOT NULL CHECK (
        jsonb_typeof(payload) = 'object' AND octet_length(payload::text) <= 16384
    ),
    request_id text NOT NULL CHECK (
        octet_length(request_id) BETWEEN 1 AND 128
        AND request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    trace_id text NOT NULL CHECK (
        octet_length(trace_id) BETWEEN 1 AND 128
        AND trace_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid,
    occurred_at timestamptz NOT NULL,
    FOREIGN KEY (actor_scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    UNIQUE (order_id, revision)
);

CREATE INDEX package_order_events_latest_idx ON package_order_events (order_id, revision DESC);

CREATE TABLE package_payment_attempts (
    id uuid PRIMARY KEY,
    order_id uuid NOT NULL REFERENCES package_orders(id) ON DELETE RESTRICT,
    attempt_no integer NOT NULL CHECK (attempt_no > 0),
    provider text NOT NULL CHECK (
        octet_length(provider) BETWEEN 1 AND 64 AND provider ~ '^[a-z][a-z0-9._-]*$'
    ),
    provider_account_id text NOT NULL CHECK (
        octet_length(provider_account_id) BETWEEN 1 AND 128
        AND provider_account_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    external_payment_id text NOT NULL CHECK (
        octet_length(external_payment_id) BETWEEN 1 AND 128
        AND external_payment_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    amount_minor bigint NOT NULL CHECK (amount_minor >= 0),
    currency text NOT NULL CHECK (currency = 'CNY'),
    request_id text NOT NULL CHECK (
        octet_length(request_id) BETWEEN 1 AND 128
        AND request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    trace_id text NOT NULL CHECK (
        octet_length(trace_id) BETWEEN 1 AND 128
        AND trace_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    created_at timestamptz NOT NULL,
    UNIQUE (order_id, attempt_no),
    UNIQUE (provider, provider_account_id, external_payment_id)
);

CREATE TABLE payment_callback_events (
    id uuid PRIMARY KEY,
    order_id uuid REFERENCES package_orders(id) ON DELETE RESTRICT,
    payment_attempt_id uuid REFERENCES package_payment_attempts(id) ON DELETE RESTRICT,
    provider text NOT NULL,
    provider_account_id text NOT NULL,
    external_event_id text NOT NULL CHECK (
        octet_length(external_event_id) BETWEEN 1 AND 128
        AND external_event_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    event_kind text NOT NULL CHECK (event_kind IN (
        'payment_succeeded', 'payment_failed', 'refund_succeeded', 'void_succeeded'
    )),
    payload_sha256 bytea NOT NULL CHECK (octet_length(payload_sha256) = 32),
    verification_key_id text NOT NULL CHECK (
        octet_length(verification_key_id) BETWEEN 1 AND 128
        AND verification_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    signature_verified boolean NOT NULL,
    sanitized_fields jsonb NOT NULL CHECK (
        jsonb_typeof(sanitized_fields) = 'object'
        AND octet_length(sanitized_fields::text) <= 4096
        AND sanitized_fields - ARRAY[
            'payment_id', 'status', 'amount_minor', 'currency', 'occurred_at'
        ]::text[] = '{}'::jsonb
        AND (
            NOT (sanitized_fields ? 'payment_id')
            OR (
                jsonb_typeof(sanitized_fields -> 'payment_id') = 'string'
                AND octet_length(sanitized_fields ->> 'payment_id') BETWEEN 1 AND 128
                AND sanitized_fields ->> 'payment_id' ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
            )
        )
        AND (
            NOT (sanitized_fields ? 'status')
            OR (
                jsonb_typeof(sanitized_fields -> 'status') = 'string'
                AND sanitized_fields ->> 'status' = event_kind
            )
        )
        AND (
            NOT (sanitized_fields ? 'amount_minor')
            OR (
                jsonb_typeof(sanitized_fields -> 'amount_minor') = 'number'
                AND sanitized_fields ->> 'amount_minor' ~ '^(0|[1-9][0-9]*)$'
                AND (sanitized_fields ->> 'amount_minor')::numeric <= 1000000000000000
            )
        )
        AND (
            NOT (sanitized_fields ? 'currency')
            OR (
                jsonb_typeof(sanitized_fields -> 'currency') = 'string'
                AND sanitized_fields ->> 'currency' = 'CNY'
            )
        )
        AND (
            NOT (sanitized_fields ? 'occurred_at')
            OR (
                jsonb_typeof(sanitized_fields -> 'occurred_at') = 'string'
                AND sanitized_fields ->> 'occurred_at' ~
                    '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})$'
            )
        )
    ),
    processing_result text NOT NULL CHECK (processing_result IN (
        'applied', 'rejected_signature', 'rejected_mismatch', 'ignored_out_of_order',
        'ignored_terminal', 'failed_fulfillment'
    )),
    received_at timestamptz NOT NULL,
    processed_at timestamptz NOT NULL CHECK (processed_at >= received_at),
    UNIQUE (provider, provider_account_id, external_event_id),
    CHECK ((order_id IS NULL) = (payment_attempt_id IS NULL))
);

ALTER TABLE billing_transactions DROP CONSTRAINT billing_transactions_operation_check;
ALTER TABLE billing_transactions
    ADD COLUMN commercial_order_id uuid REFERENCES package_orders(id) ON DELETE RESTRICT,
    ADD COLUMN reverses_transaction_id uuid REFERENCES billing_transactions(id) ON DELETE RESTRICT,
    ADD COLUMN payment_attempt_id uuid REFERENCES package_payment_attempts(id) ON DELETE RESTRICT,
    ADD CONSTRAINT billing_transactions_operation_check CHECK (operation IN (
        'manual_adjustment', 'provider_payment', 'package_purchase', 'package_renewal',
        'package_upgrade', 'package_downgrade', 'package_refund', 'package_void',
        'traffic_package_purchase'
    )),
    ADD CONSTRAINT billing_transactions_commerce_shape CHECK (
        (operation = 'manual_adjustment'
            AND commercial_order_id IS NULL
            AND reverses_transaction_id IS NULL
            AND payment_attempt_id IS NULL)
        OR
        (operation = 'provider_payment'
            AND commercial_order_id IS NOT NULL
            AND reverses_transaction_id IS NULL
            AND payment_attempt_id IS NOT NULL
            AND direction = 'credit')
        OR
        (operation IN ('package_purchase', 'package_renewal', 'package_upgrade',
                       'package_downgrade', 'traffic_package_purchase')
            AND commercial_order_id IS NOT NULL
            AND reverses_transaction_id IS NULL)
        OR
        (operation IN ('package_refund', 'package_void')
            AND commercial_order_id IS NOT NULL
            AND reverses_transaction_id IS NOT NULL
            AND direction = 'credit')
    );

CREATE INDEX billing_transactions_commercial_order_idx
    ON billing_transactions (commercial_order_id, created_at, id)
    WHERE commercial_order_id IS NOT NULL;
CREATE INDEX billing_transactions_reversal_idx
    ON billing_transactions (reverses_transaction_id, created_at, id)
    WHERE reverses_transaction_id IS NOT NULL;

CREATE TABLE package_balance_holds (
    id uuid PRIMARY KEY,
    order_id uuid NOT NULL UNIQUE REFERENCES package_orders(id) ON DELETE RESTRICT,
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    currency text NOT NULL CHECK (currency = 'CNY'),
    amount_minor bigint NOT NULL CHECK (amount_minor > 0),
    effective_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL CHECK (expires_at > effective_at),
    created_at timestamptz NOT NULL
);

CREATE TABLE package_balance_hold_events (
    id uuid PRIMARY KEY,
    hold_id uuid NOT NULL REFERENCES package_balance_holds(id) ON DELETE RESTRICT,
    revision bigint NOT NULL CHECK (revision > 0),
    event_type text NOT NULL CHECK (event_type IN ('reserved', 'captured', 'released', 'expired')),
    occurred_at timestamptz NOT NULL,
    UNIQUE (hold_id, revision)
);

CREATE TABLE package_order_fulfillments (
    id uuid PRIMARY KEY,
    order_id uuid NOT NULL UNIQUE REFERENCES package_orders(id) ON DELETE RESTRICT,
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    billing_transaction_id uuid REFERENCES billing_transactions(id) ON DELETE RESTRICT,
    balance_hold_id uuid REFERENCES package_balance_holds(id) ON DELETE RESTRICT,
    subscription_id uuid REFERENCES package_subscriptions(id) ON DELETE RESTRICT,
    subscription_revision bigint,
    entitlement_revision bigint,
    traffic_grant_id uuid REFERENCES traffic_package_grants(id) ON DELETE RESTRICT,
    fulfilled_at timestamptz NOT NULL,
    CHECK (
        (subscription_id IS NOT NULL AND subscription_revision IS NOT NULL
            AND entitlement_revision IS NOT NULL AND traffic_grant_id IS NULL)
        OR
        (subscription_id IS NULL AND subscription_revision IS NULL
            AND entitlement_revision IS NULL AND traffic_grant_id IS NOT NULL)
    ),
    CHECK (billing_transaction_id IS NULL OR balance_hold_id IS NULL)
);

CREATE TABLE package_subscription_entitlement_versions (
    subscription_id uuid NOT NULL REFERENCES package_subscriptions(id) ON DELETE RESTRICT,
    revision bigint NOT NULL CHECK (revision > 0),
    supersedes_subscription_id uuid,
    supersedes_revision bigint,
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    effective_at timestamptz NOT NULL,
    effective_until timestamptz,
    product_id uuid NOT NULL,
    product_revision bigint NOT NULL CHECK (product_revision > 0),
    product_snapshot jsonb NOT NULL CHECK (
        jsonb_typeof(product_snapshot) = 'object' AND octet_length(product_snapshot::text) <= 65536
    ),
    site_limit bigint NOT NULL CHECK (site_limit = -1 OR site_limit BETWEEN 0 AND 1000000000),
    domain_limit bigint NOT NULL CHECK (domain_limit = -1 OR domain_limit BETWEEN 0 AND 1000000000),
    node_limit bigint NOT NULL CHECK (node_limit = -1 OR node_limit BETWEEN 0 AND 1000000000),
    traffic_limit_bytes bigint NOT NULL CHECK (traffic_limit_bytes = -1 OR traffic_limit_bytes >= 0),
    timezone text NOT NULL CHECK (is_valid_package_subscription_timezone(timezone)),
    cycle_kind text NOT NULL CHECK (cycle_kind IN ('daily', 'monthly', 'custom_days')),
    custom_cycle_days integer NOT NULL DEFAULT 0 CHECK (
        (cycle_kind IN ('daily', 'monthly') AND custom_cycle_days = 0)
        OR (cycle_kind = 'custom_days' AND custom_cycle_days BETWEEN 1 AND 366)
    ),
    tcp_factor_numerator bigint NOT NULL CHECK (tcp_factor_numerator BETWEEN 1 AND 1000000),
    tcp_factor_denominator bigint NOT NULL CHECK (tcp_factor_denominator BETWEEN 1 AND 1000000),
    package_period text CHECK (package_period IS NULL OR package_period IN ('month', 'quarter', 'year')),
    period_price_minor bigint CHECK (period_price_minor IS NULL OR period_price_minor >= 0),
    currency text NOT NULL CHECK (currency = 'CNY'),
    entitlement_status text NOT NULL CHECK (entitlement_status IN ('active', 'revoked')),
    source_order_id uuid REFERENCES package_orders(id) ON DELETE RESTRICT,
    operation text NOT NULL CHECK (operation IN (
        'migration_backfill', 'purchase', 'renew', 'upgrade', 'downgrade', 'refund', 'void'
    )),
    created_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (subscription_id, revision),
    UNIQUE (supersedes_subscription_id, supersedes_revision),
    UNIQUE (subscription_id, effective_at, revision),
    FOREIGN KEY (supersedes_subscription_id, supersedes_revision)
        REFERENCES package_subscription_entitlement_versions(subscription_id, revision)
        ON DELETE RESTRICT,
    FOREIGN KEY (product_id, product_revision)
        REFERENCES package_product_versions(product_id, revision) ON DELETE RESTRICT,
    CHECK (
        (revision = 1 AND supersedes_subscription_id IS NULL AND supersedes_revision IS NULL)
        OR
        (revision > 1 AND supersedes_subscription_id IS NOT NULL AND supersedes_revision IS NOT NULL)
    ),
    CHECK (effective_until IS NULL OR effective_until > effective_at),
    CHECK (tcp_factor_numerator::numeric <= tcp_factor_denominator::numeric * 1000),
    CHECK ((operation = 'migration_backfill') = (source_order_id IS NULL))
);

CREATE INDEX package_subscription_entitlement_effective_idx
    ON package_subscription_entitlement_versions (subscription_id, effective_at DESC, revision DESC);
CREATE INDEX package_subscription_entitlement_order_idx
    ON package_subscription_entitlement_versions (source_order_id)
    WHERE source_order_id IS NOT NULL;

INSERT INTO package_subscription_entitlement_versions (
    subscription_id, revision, supersedes_subscription_id, supersedes_revision,
    tenant_scope_id, effective_at, effective_until,
    product_id, product_revision, product_snapshot,
    site_limit, domain_limit, node_limit, traffic_limit_bytes,
    timezone, cycle_kind, custom_cycle_days, tcp_factor_numerator, tcp_factor_denominator,
    package_period, period_price_minor, currency, entitlement_status,
    source_order_id, operation, created_by_user_id, created_at
)
SELECT id, 1, NULL, NULL, tenant_scope_id, starts_at, NULL,
       product_id, product_revision, product_snapshot,
       site_limit, domain_limit, node_limit, traffic_limit_bytes,
       timezone, cycle_kind, custom_cycle_days, tcp_factor_numerator, tcp_factor_denominator,
       NULL, NULL, 'CNY', CASE lifecycle_status WHEN 'cancelled' THEN 'revoked' ELSE 'active' END,
       NULL, 'migration_backfill', created_by_user_id, created_at
FROM package_subscriptions;

CREATE FUNCTION package_subscription_effective_entitlement_revision(
    target_subscription_id uuid,
    at_time timestamptz
)
RETURNS bigint
LANGUAGE sql
STABLE
AS $$
    SELECT candidate.revision
    FROM package_subscription_entitlement_versions candidate
    WHERE candidate.subscription_id = target_subscription_id
      AND candidate.effective_at <= at_time
      AND (candidate.effective_until IS NULL OR candidate.effective_until > at_time)
      AND NOT EXISTS (
          SELECT 1
          FROM package_subscription_entitlement_versions later
          WHERE later.subscription_id = candidate.subscription_id
            AND later.revision > candidate.revision
            AND later.effective_at <= at_time
      )
    ORDER BY candidate.revision DESC
    LIMIT 1
$$;

ALTER TABLE package_subscription_versions DROP CONSTRAINT package_subscription_versions_operation_check;
ALTER TABLE package_subscription_versions
    ADD COLUMN order_id uuid REFERENCES package_orders(id) ON DELETE RESTRICT,
    ADD COLUMN entitlement_revision bigint,
    ADD CONSTRAINT package_subscription_versions_operation_check
        CHECK (operation IN ('open', 'renew', 'cancel', 'upgrade', 'downgrade')),
    ADD CONSTRAINT package_subscription_versions_commerce_shape CHECK (
        (operation IN ('open', 'cancel') AND order_id IS NULL AND entitlement_revision IS NULL)
        OR
        (operation = 'renew' AND ((order_id IS NULL AND entitlement_revision IS NULL)
            OR (order_id IS NOT NULL AND entitlement_revision IS NOT NULL)))
        OR
        (operation IN ('upgrade', 'downgrade')
            AND order_id IS NOT NULL AND entitlement_revision IS NOT NULL)
    ),
    ADD CONSTRAINT package_subscription_versions_entitlement_fk
        FOREIGN KEY (subscription_id, entitlement_revision)
        REFERENCES package_subscription_entitlement_versions(subscription_id, revision)
        ON DELETE RESTRICT;

ALTER TABLE traffic_package_grants
    ADD COLUMN billing_transaction_id uuid REFERENCES billing_transactions(id) ON DELETE RESTRICT,
    ADD COLUMN commerce_order_id uuid REFERENCES package_orders(id) ON DELETE RESTRICT,
    ADD CONSTRAINT traffic_package_grants_commerce_pair CHECK (
        (commerce_order_id IS NULL AND billing_transaction_id IS NULL)
        OR (commerce_order_id IS NOT NULL AND (price_minor = 0 OR billing_transaction_id IS NOT NULL))
    );

ALTER TABLE promotion_adjustment_decisions
    ADD COLUMN billing_transaction_id uuid UNIQUE REFERENCES billing_transactions(id) ON DELETE RESTRICT;

CREATE TABLE package_commerce_write_requests (
    id uuid PRIMARY KEY,
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    target_tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    operation text NOT NULL CHECK (operation IN (
        'package.commerce.purchase', 'package.commerce.renew',
        'package.commerce.upgrade', 'package.commerce.downgrade',
        'package.commerce.traffic_package.purchase',
        'package.commerce.refund', 'package.commerce.void'
    )),
    idempotency_key text NOT NULL CHECK (
        octet_length(idempotency_key) BETWEEN 1 AND 128
        AND idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    order_id uuid REFERENCES package_orders(id) ON DELETE RESTRICT,
    response_body jsonb CHECK (response_body IS NULL OR jsonb_typeof(response_body) = 'object'),
    created_at timestamptz NOT NULL,
    completed_at timestamptz,
    FOREIGN KEY (actor_scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    UNIQUE (actor_scope_id, actor_user_id, operation, idempotency_key),
    CHECK (
        (completed_at IS NULL AND order_id IS NULL AND response_body IS NULL)
        OR (completed_at IS NOT NULL AND order_id IS NOT NULL AND response_body IS NOT NULL)
    )
);

CREATE TABLE package_commerce_manual_approvals (
    id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    order_id uuid NOT NULL REFERENCES package_orders(id) ON DELETE RESTRICT,
    operation text NOT NULL CHECK (operation IN ('refund', 'void')),
    requested_by_scope_id uuid NOT NULL,
    requested_by_user_id uuid NOT NULL,
    approved_by_scope_id uuid NOT NULL,
    approved_by_user_id uuid NOT NULL,
    requested_step_up_at timestamptz NOT NULL,
    approved_step_up_at timestamptz NOT NULL,
    reason_code text NOT NULL CHECK (
        octet_length(reason_code) BETWEEN 1 AND 128
        AND reason_code ~ '^[a-z][a-z0-9._-]*$'
    ),
    request_id text NOT NULL CHECK (
        octet_length(request_id) BETWEEN 1 AND 128
        AND request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL CHECK (expires_at > created_at),
    FOREIGN KEY (requested_by_scope_id, requested_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY (approved_by_scope_id, approved_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    CHECK (requested_by_user_id <> approved_by_user_id),
    CHECK (requested_step_up_at <= created_at AND approved_step_up_at <= created_at)
);

CREATE TABLE package_commerce_approval_uses (
    id uuid PRIMARY KEY,
    approval_id uuid NOT NULL UNIQUE
        REFERENCES package_commerce_manual_approvals(id) ON DELETE RESTRICT,
    order_id uuid NOT NULL REFERENCES package_orders(id) ON DELETE RESTRICT,
    billing_transaction_id uuid NOT NULL UNIQUE
        REFERENCES billing_transactions(id) ON DELETE RESTRICT,
    used_at timestamptz NOT NULL
);

CREATE TABLE package_commerce_outbox (
    id uuid PRIMARY KEY,
    aggregate_type text NOT NULL CHECK (aggregate_type IN ('package_order', 'payment_callback')),
    aggregate_id uuid NOT NULL,
    event_type text NOT NULL CHECK (
        octet_length(event_type) BETWEEN 1 AND 128 AND event_type ~ '^[a-z][a-z0-9._-]*$'
    ),
    payload jsonb NOT NULL CHECK (
        jsonb_typeof(payload) = 'object' AND octet_length(payload::text) <= 16384
    ),
    request_id text NOT NULL,
    trace_id text NOT NULL,
    created_at timestamptz NOT NULL,
    UNIQUE (aggregate_type, aggregate_id, event_type, request_id)
);

CREATE FUNCTION prevent_package_commerce_fact_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'TRUNCATE' THEN
        RAISE EXCEPTION '% cannot be truncated', TG_TABLE_NAME;
    END IF;
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME;
END;
$$;

CREATE FUNCTION protect_package_commerce_write_request()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'TRUNCATE' THEN
        RAISE EXCEPTION 'package commerce write requests cannot be truncated';
    ELSIF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'package commerce write requests cannot be deleted';
    ELSIF TG_OP = 'INSERT' THEN
        IF NEW.order_id IS NOT NULL OR NEW.response_body IS NOT NULL OR NEW.completed_at IS NOT NULL THEN
            RAISE EXCEPTION 'package commerce write request must start unfinished';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.completed_at IS NOT NULL
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.actor_scope_id IS DISTINCT FROM OLD.actor_scope_id
       OR NEW.actor_user_id IS DISTINCT FROM OLD.actor_user_id
       OR NEW.target_tenant_scope_id IS DISTINCT FROM OLD.target_tenant_scope_id
       OR NEW.operation IS DISTINCT FROM OLD.operation
       OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key
       OR NEW.request_digest IS DISTINCT FROM OLD.request_digest
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.order_id IS NULL OR NEW.response_body IS NULL OR NEW.completed_at IS NULL
       OR NEW.completed_at < OLD.created_at THEN
        RAISE EXCEPTION 'package commerce write request must complete atomically';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION validate_package_order_event()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE previous_type text;
DECLARE previous_revision bigint;
DECLARE previous_time timestamptz;
BEGIN
    PERFORM 1 FROM package_orders WHERE id = NEW.order_id FOR UPDATE;
    SELECT event_type, revision, occurred_at
    INTO previous_type, previous_revision, previous_time
    FROM package_order_events
    WHERE order_id = NEW.order_id
    ORDER BY revision DESC LIMIT 1;
    IF previous_revision IS NULL THEN
        IF NEW.revision <> 1 OR NEW.event_type <> 'created' THEN
            RAISE EXCEPTION 'package order must start with created revision 1';
        END IF;
    ELSE
        IF NEW.revision <> previous_revision + 1 OR NEW.occurred_at < previous_time THEN
            RAISE EXCEPTION 'package order event revision or time is not monotonic';
        END IF;
        IF (previous_type = 'created' AND NEW.event_type NOT IN ('paid', 'cancelled', 'failed'))
           OR (previous_type = 'paid' AND NEW.event_type NOT IN ('fulfilled', 'void_applied', 'failed'))
           OR (previous_type = 'fulfilled' AND NEW.event_type NOT IN ('refund_applied', 'void_applied'))
           OR (previous_type = 'refund_applied' AND NEW.event_type <> 'refund_applied')
           OR previous_type IN ('cancelled', 'void_applied', 'failed') THEN
            RAISE EXCEPTION 'invalid package order state transition from % to %', previous_type, NEW.event_type;
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION assert_package_order_event_audited()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE tenant_id uuid;
BEGIN
    SELECT tenant_scope_id INTO tenant_id FROM package_orders WHERE id = NEW.order_id;
    IF NOT EXISTS (
        SELECT 1 FROM audit_events
        WHERE scope_id = tenant_id
          AND action = 'package.commerce.order.' || NEW.event_type
          AND resource_id = NEW.order_id::text
          AND request_id = NEW.request_id
          AND result = 'success'
    ) THEN
        RAISE EXCEPTION 'package order event requires matching audit';
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION assert_package_commercial_transaction()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE original_target uuid;
DECLARE original_currency text;
DECLARE original_order uuid;
DECLARE original_amount bigint;
DECLARE original_operation text;
DECLARE reversal_total numeric;
DECLARE order_tenant uuid;
DECLARE order_currency text;
DECLARE order_amount bigint;
BEGIN
    IF NEW.operation = 'manual_adjustment' THEN
        RETURN NULL;
    END IF;
    SELECT tenant_scope_id, currency, payable_amount_minor
    INTO order_tenant, order_currency, order_amount
    FROM package_orders WHERE id = NEW.commercial_order_id;
    IF order_tenant IS DISTINCT FROM NEW.target_scope_id
       OR order_currency IS DISTINCT FROM NEW.currency
       OR (NEW.operation <> 'package_refund' AND NEW.operation <> 'package_void'
           AND NEW.amount_minor <> order_amount) THEN
        RAISE EXCEPTION 'commercial billing transaction does not match order';
    END IF;
    IF NEW.operation IN ('package_refund', 'package_void') THEN
        SELECT target_scope_id, currency, commercial_order_id, amount_minor, operation
        INTO original_target, original_currency, original_order, original_amount, original_operation
        FROM billing_transactions WHERE id = NEW.reverses_transaction_id;
        IF original_operation NOT IN ('package_purchase', 'package_renewal', 'package_upgrade',
                                      'package_downgrade', 'traffic_package_purchase')
           OR original_target IS DISTINCT FROM NEW.target_scope_id
           OR original_currency IS DISTINCT FROM NEW.currency
           OR original_order IS DISTINCT FROM NEW.commercial_order_id THEN
            RAISE EXCEPTION 'commercial reversal does not match original sale';
        END IF;
        SELECT COALESCE(sum(amount_minor::numeric), 0)
        INTO reversal_total FROM billing_transactions
        WHERE reverses_transaction_id = NEW.reverses_transaction_id;
        IF reversal_total > original_amount
           OR (NEW.operation = 'package_void' AND
               (reversal_total <> original_amount OR
                (SELECT count(*) FROM billing_transactions
                 WHERE reverses_transaction_id = NEW.reverses_transaction_id) <> 1)) THEN
            RAISE EXCEPTION 'commercial reversal exceeds original sale';
        END IF;
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION validate_package_entitlement_version()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE expected_revision bigint;
DECLARE previous_revision bigint;
DECLARE previous_created_at timestamptz;
DECLARE previous_effective_at timestamptz;
DECLARE subscription_tenant uuid;
DECLARE subscription_start timestamptz;
DECLARE order_tenant uuid;
DECLARE order_subscription uuid;
BEGIN
    SELECT tenant_scope_id, starts_at
    INTO subscription_tenant, subscription_start
    FROM package_subscriptions WHERE id = NEW.subscription_id FOR UPDATE;
    SELECT revision, created_at, effective_at
    INTO previous_revision, previous_created_at, previous_effective_at
    FROM package_subscription_entitlement_versions
    WHERE subscription_id = NEW.subscription_id
    ORDER BY revision DESC LIMIT 1;
    expected_revision := COALESCE(previous_revision, 0) + 1;
    IF NEW.revision <> expected_revision
       OR NEW.tenant_scope_id IS DISTINCT FROM subscription_tenant
       OR NEW.effective_at < subscription_start THEN
        RAISE EXCEPTION 'invalid package entitlement revision, tenant, or effective time';
    END IF;
    IF previous_revision IS NULL THEN
        IF NEW.supersedes_subscription_id IS NOT NULL OR NEW.supersedes_revision IS NOT NULL THEN
            RAISE EXCEPTION 'first package entitlement revision cannot supersede another fact';
        END IF;
    ELSIF NEW.supersedes_subscription_id IS DISTINCT FROM NEW.subscription_id
          OR NEW.supersedes_revision IS DISTINCT FROM previous_revision
          OR NEW.effective_at < previous_effective_at
          OR NEW.created_at < previous_created_at THEN
        RAISE EXCEPTION 'package entitlement must supersede the current linear-chain head';
    END IF;
    IF NEW.source_order_id IS NOT NULL THEN
        SELECT tenant_scope_id, subscription_id INTO order_tenant, order_subscription
        FROM package_orders WHERE id = NEW.source_order_id;
        IF order_tenant IS DISTINCT FROM NEW.tenant_scope_id
           OR (order_subscription IS NOT NULL AND order_subscription IS DISTINCT FROM NEW.subscription_id) THEN
            RAISE EXCEPTION 'package entitlement source order does not match subscription';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION assert_package_subscription_revision_fact()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE fact_operation text;
BEGIN
    SELECT operation INTO fact_operation
    FROM package_subscription_versions
    WHERE subscription_id = NEW.id AND revision = NEW.revision;
    IF fact_operation IS NULL
       OR (NEW.lifecycle_status = 'cancelled' AND fact_operation <> 'cancel')
       OR (NEW.lifecycle_status = 'active' AND NEW.ends_at > OLD.ends_at AND fact_operation <> 'renew')
       OR (NEW.lifecycle_status = 'active' AND NEW.ends_at = OLD.ends_at
           AND fact_operation NOT IN ('upgrade', 'downgrade')) THEN
        RAISE EXCEPTION 'package subscription revision requires matching version fact';
    END IF;
    RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION protect_package_subscription_snapshot()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.tenant_scope_id IS DISTINCT FROM OLD.tenant_scope_id
       OR NEW.product_id IS DISTINCT FROM OLD.product_id
       OR NEW.product_revision IS DISTINCT FROM OLD.product_revision
       OR NEW.product_snapshot IS DISTINCT FROM OLD.product_snapshot
       OR NEW.site_limit IS DISTINCT FROM OLD.site_limit
       OR NEW.domain_limit IS DISTINCT FROM OLD.domain_limit
       OR NEW.node_limit IS DISTINCT FROM OLD.node_limit
       OR NEW.traffic_limit_bytes IS DISTINCT FROM OLD.traffic_limit_bytes
       OR NEW.starts_at IS DISTINCT FROM OLD.starts_at
       OR NEW.timezone IS DISTINCT FROM OLD.timezone
       OR NEW.cycle_kind IS DISTINCT FROM OLD.cycle_kind
       OR NEW.custom_cycle_days IS DISTINCT FROM OLD.custom_cycle_days
       OR NEW.tcp_factor_numerator IS DISTINCT FROM OLD.tcp_factor_numerator
       OR NEW.tcp_factor_denominator IS DISTINCT FROM OLD.tcp_factor_denominator
       OR NEW.created_by_user_id IS DISTINCT FROM OLD.created_by_user_id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'package subscription snapshot is immutable';
    END IF;
    IF OLD.lifecycle_status = 'cancelled' THEN
        RAISE EXCEPTION 'cancelled package subscription is immutable';
    END IF;
    IF NEW.revision <> OLD.revision + 1 THEN
        RAISE EXCEPTION 'package subscription revision must advance by one';
    END IF;
    IF NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'package subscription updated_at cannot move backwards';
    END IF;
    IF NEW.lifecycle_status = 'active' THEN
        IF NEW.ends_at < OLD.ends_at OR NEW.cancelled_at IS NOT NULL THEN
            RAISE EXCEPTION 'active package subscription renewal must strictly extend ends_at';
        END IF;
    ELSIF NEW.lifecycle_status = 'cancelled' THEN
        IF NEW.ends_at IS DISTINCT FROM OLD.ends_at
           OR NEW.cancelled_at IS DISTINCT FROM NEW.updated_at
           OR NEW.cancelled_at < OLD.updated_at THEN
            RAISE EXCEPTION 'package subscription cancellation facts are invalid';
        END IF;
    ELSE
        RAISE EXCEPTION 'invalid package subscription lifecycle transition';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION protect_traffic_package_grant()
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
       OR NEW.billing_transaction_id IS DISTINCT FROM OLD.billing_transaction_id
       OR NEW.commerce_order_id IS DISTINCT FROM OLD.commerce_order_id
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

CREATE FUNCTION assert_traffic_package_commerce_grant()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE transaction_tenant uuid;
DECLARE transaction_currency text;
DECLARE transaction_amount bigint;
DECLARE transaction_order uuid;
DECLARE order_original bigint;
DECLARE order_snapshot uuid;
BEGIN
    IF NEW.commerce_order_id IS NULL THEN
        RETURN NULL;
    END IF;
    SELECT target_scope_id, currency, amount_minor, commercial_order_id
    INTO transaction_tenant, transaction_currency, transaction_amount, transaction_order
    FROM billing_transactions WHERE id = NEW.billing_transaction_id;
    SELECT original_amount_minor, traffic_product_snapshot_id
    INTO order_original, order_snapshot
    FROM package_orders WHERE id = NEW.commerce_order_id;
    IF order_original IS DISTINCT FROM NEW.price_minor
       OR order_snapshot IS DISTINCT FROM NEW.product_snapshot_id THEN
        RAISE EXCEPTION 'traffic package grant does not match commerce order';
    END IF;
    IF NEW.billing_transaction_id IS NULL THEN
        IF NEW.price_minor <> 0 THEN
            RAISE EXCEPTION 'paid traffic package grant requires billing transaction';
        END IF;
        RETURN NULL;
    END IF;
    IF transaction_tenant IS DISTINCT FROM NEW.tenant_scope_id
       OR transaction_currency IS DISTINCT FROM NEW.currency
       OR transaction_order IS DISTINCT FROM NEW.commerce_order_id
       OR transaction_amount IS DISTINCT FROM (
           SELECT payable_amount_minor FROM package_orders WHERE id = NEW.commerce_order_id
       ) THEN
        RAISE EXCEPTION 'traffic package grant does not match commerce payment';
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION validate_package_balance_hold_event()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE previous_type text;
DECLARE previous_revision bigint;
BEGIN
    PERFORM 1 FROM package_balance_holds WHERE id = NEW.hold_id FOR UPDATE;
    SELECT event_type, revision INTO previous_type, previous_revision
    FROM package_balance_hold_events WHERE hold_id = NEW.hold_id
    ORDER BY revision DESC LIMIT 1;
    IF previous_revision IS NULL THEN
        IF NEW.revision <> 1 OR NEW.event_type <> 'reserved' THEN
            RAISE EXCEPTION 'balance hold must start reserved';
        END IF;
    ELSIF previous_type <> 'reserved' OR NEW.revision <> previous_revision + 1
          OR NEW.event_type = 'reserved' THEN
        RAISE EXCEPTION 'invalid balance hold transition';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION assert_package_commerce_manual_approval()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE requested_kind text;
DECLARE approved_kind text;
DECLARE order_tenant uuid;
BEGIN
    SELECT kind INTO requested_kind FROM access_scopes WHERE id = NEW.requested_by_scope_id;
    SELECT kind INTO approved_kind FROM access_scopes WHERE id = NEW.approved_by_scope_id;
    SELECT tenant_scope_id INTO order_tenant FROM package_orders WHERE id = NEW.order_id;
    IF requested_kind IS DISTINCT FROM 'platform' OR approved_kind IS DISTINCT FROM 'platform'
       OR order_tenant IS DISTINCT FROM NEW.tenant_scope_id THEN
        RAISE EXCEPTION 'manual commerce approval requires two platform actors and matching tenant';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER package_order_events_validate
BEFORE INSERT ON package_order_events
FOR EACH ROW EXECUTE FUNCTION validate_package_order_event();
CREATE CONSTRAINT TRIGGER package_order_events_audited
AFTER INSERT ON package_order_events
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION assert_package_order_event_audited();
CREATE CONSTRAINT TRIGGER billing_transactions_commercial_valid
AFTER INSERT ON billing_transactions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION assert_package_commercial_transaction();
CREATE TRIGGER package_entitlement_versions_validate
BEFORE INSERT ON package_subscription_entitlement_versions
FOR EACH ROW EXECUTE FUNCTION validate_package_entitlement_version();
CREATE CONSTRAINT TRIGGER package_subscriptions_revision_fact
AFTER UPDATE ON package_subscriptions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION assert_package_subscription_revision_fact();
CREATE CONSTRAINT TRIGGER traffic_package_grants_commerce_valid
AFTER INSERT ON traffic_package_grants
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION assert_traffic_package_commerce_grant();
CREATE TRIGGER package_balance_hold_events_validate
BEFORE INSERT ON package_balance_hold_events
FOR EACH ROW EXECUTE FUNCTION validate_package_balance_hold_event();
CREATE TRIGGER package_commerce_manual_approvals_validate
BEFORE INSERT ON package_commerce_manual_approvals
FOR EACH ROW EXECUTE FUNCTION assert_package_commerce_manual_approval();
CREATE TRIGGER package_commerce_write_requests_protect
BEFORE INSERT OR UPDATE OR DELETE ON package_commerce_write_requests
FOR EACH ROW EXECUTE FUNCTION protect_package_commerce_write_request();
CREATE TRIGGER package_commerce_write_requests_no_truncate
BEFORE TRUNCATE ON package_commerce_write_requests
FOR EACH STATEMENT EXECUTE FUNCTION protect_package_commerce_write_request();

DO $$
DECLARE table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'package_orders', 'package_order_events', 'package_payment_attempts',
        'payment_callback_events', 'package_balance_holds', 'package_balance_hold_events',
        'package_order_fulfillments', 'package_subscription_entitlement_versions',
        'package_commerce_manual_approvals', 'package_commerce_approval_uses',
        'package_commerce_outbox'
    ] LOOP
        EXECUTE format(
            'CREATE TRIGGER %I_append_only BEFORE UPDATE OR DELETE ON %I '
            'FOR EACH ROW EXECUTE FUNCTION prevent_package_commerce_fact_mutation()',
            table_name, table_name
        );
        EXECUTE format(
            'CREATE TRIGGER %I_no_truncate BEFORE TRUNCATE ON %I '
            'FOR EACH STATEMENT EXECUTE FUNCTION prevent_package_commerce_fact_mutation()',
            table_name, table_name
        );
    END LOOP;
END;
$$;
