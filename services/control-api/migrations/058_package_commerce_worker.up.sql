LOCK TABLE package_commerce_outbox IN SHARE ROW EXCLUSIVE MODE;

ALTER TABLE billing_transactions
    ADD COLUMN balance_hold_id uuid REFERENCES package_balance_holds(id) ON DELETE RESTRICT,
    ADD CONSTRAINT billing_transactions_balance_hold_shape CHECK (
        balance_hold_id IS NULL OR (
            operation IN ('package_upgrade', 'package_downgrade')
            AND direction = 'debit'
            AND commercial_order_id IS NOT NULL
            AND reverses_transaction_id IS NULL
            AND payment_attempt_id IS NULL
        )
    );

CREATE UNIQUE INDEX billing_transactions_balance_hold_idx
    ON billing_transactions (balance_hold_id) WHERE balance_hold_id IS NOT NULL;

CREATE TABLE package_commerce_outbox_deliveries (
    outbox_id uuid PRIMARY KEY REFERENCES package_commerce_outbox(id) ON DELETE RESTRICT,
    state text NOT NULL CHECK (state IN (
        'pending', 'leased', 'completed', 'permanent_failure', 'exhausted'
    )),
    available_at timestamptz NOT NULL,
    lease_owner text CHECK (
        lease_owner IS NULL OR (
            octet_length(lease_owner) BETWEEN 1 AND 128
            AND lease_owner ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
        )
    ),
    lease_token uuid,
    lease_fence bigint NOT NULL DEFAULT 0 CHECK (lease_fence >= 0),
    lease_expires_at timestamptz,
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count BETWEEN 0 AND 1000000),
    completed_at timestamptz,
    last_result_code text CHECK (
        last_result_code IS NULL OR (
            octet_length(last_result_code) BETWEEN 1 AND 128
            AND last_result_code ~ '^[a-z][a-z0-9._-]*$'
        )
    ),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CHECK (updated_at >= created_at),
    CHECK (
        (state = 'pending'
            AND lease_owner IS NULL AND lease_token IS NULL
            AND lease_expires_at IS NULL AND completed_at IS NULL)
        OR
        (state = 'leased'
            AND lease_owner IS NOT NULL AND lease_token IS NOT NULL
            AND lease_fence > 0 AND lease_expires_at IS NOT NULL
            AND lease_expires_at > updated_at AND completed_at IS NULL)
        OR
        (state IN ('completed', 'permanent_failure', 'exhausted')
            AND lease_owner IS NULL AND lease_token IS NULL
            AND lease_expires_at IS NULL AND completed_at IS NOT NULL
            AND completed_at >= created_at AND last_result_code IS NOT NULL)
    )
);

CREATE INDEX package_commerce_outbox_deliveries_pending_idx
    ON package_commerce_outbox_deliveries (available_at, outbox_id)
    WHERE state = 'pending';
CREATE INDEX package_commerce_outbox_deliveries_lease_idx
    ON package_commerce_outbox_deliveries (lease_expires_at, outbox_id)
    WHERE state = 'leased';

CREATE TABLE package_commerce_outbox_attempts (
    id uuid PRIMARY KEY,
    outbox_id uuid NOT NULL
        REFERENCES package_commerce_outbox_deliveries(outbox_id) ON DELETE RESTRICT,
    attempt_no integer NOT NULL CHECK (attempt_no BETWEEN 1 AND 1000000),
    lease_owner text NOT NULL CHECK (
        octet_length(lease_owner) BETWEEN 1 AND 128
        AND lease_owner ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    lease_token uuid NOT NULL,
    lease_fence bigint NOT NULL CHECK (lease_fence > 0),
    leased_at timestamptz NOT NULL,
    lease_expires_at timestamptz NOT NULL CHECK (lease_expires_at > leased_at),
    result text NOT NULL CHECK (result IN (
        'leased', 'confirmed', 'unknown', 'retryable_failure',
        'permanent_failure', 'exhausted', 'canceled', 'lease_expired'
    )),
    result_code text CHECK (
        result_code IS NULL OR (
            octet_length(result_code) BETWEEN 1 AND 128
            AND result_code ~ '^[a-z][a-z0-9._-]*$'
        )
    ),
    next_attempt_at timestamptz,
    completed_at timestamptz,
    UNIQUE (outbox_id, attempt_no),
    UNIQUE (outbox_id, lease_fence),
    UNIQUE (lease_token),
    CHECK (
        (result = 'leased'
            AND result_code IS NULL AND next_attempt_at IS NULL AND completed_at IS NULL)
        OR
        (result IN ('unknown', 'retryable_failure', 'canceled', 'lease_expired')
            AND result_code IS NOT NULL AND next_attempt_at IS NOT NULL
            AND completed_at IS NOT NULL AND completed_at >= leased_at)
        OR
        (result IN ('confirmed', 'permanent_failure', 'exhausted')
            AND result_code IS NOT NULL AND next_attempt_at IS NULL
            AND completed_at IS NOT NULL AND completed_at >= leased_at)
    )
);

CREATE INDEX package_commerce_outbox_attempts_outbox_idx
    ON package_commerce_outbox_attempts (outbox_id, attempt_no DESC);

CREATE TABLE package_balance_hold_settlements (
    id uuid PRIMARY KEY,
    hold_id uuid NOT NULL UNIQUE REFERENCES package_balance_holds(id) ON DELETE RESTRICT,
    hold_revision bigint NOT NULL CHECK (hold_revision > 1),
    order_id uuid NOT NULL REFERENCES package_orders(id) ON DELETE RESTRICT,
    order_revision bigint NOT NULL CHECK (order_revision > 0),
    outcome text NOT NULL CHECK (outcome IN ('captured', 'released', 'expired')),
    billing_transaction_id uuid UNIQUE
        REFERENCES billing_transactions(id) ON DELETE RESTRICT,
    reason_code text NOT NULL CHECK (
        octet_length(reason_code) BETWEEN 1 AND 128
        AND reason_code ~ '^[a-z][a-z0-9._-]*$'
    ),
    request_id text NOT NULL CHECK (
        octet_length(request_id) BETWEEN 1 AND 128
        AND request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    trace_id text NOT NULL CHECK (
        octet_length(trace_id) BETWEEN 1 AND 128
        AND trace_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    occurred_at timestamptz NOT NULL,
    CHECK ((outcome = 'captured') = (billing_transaction_id IS NOT NULL))
);

CREATE FUNCTION enqueue_package_commerce_outbox_delivery()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO package_commerce_outbox_deliveries (
        outbox_id, state, available_at, lease_fence, attempt_count, created_at, updated_at
    ) VALUES (NEW.id, 'pending', NEW.created_at, 0, 0, NEW.created_at, NEW.created_at);
    RETURN NULL;
END;
$$;

INSERT INTO package_commerce_outbox_deliveries (
    outbox_id, state, available_at, lease_fence, attempt_count, created_at, updated_at
)
SELECT id, 'pending', created_at, 0, 0, created_at, created_at
FROM package_commerce_outbox;

CREATE TRIGGER package_commerce_outbox_enqueue_delivery
AFTER INSERT ON package_commerce_outbox
FOR EACH ROW EXECUTE FUNCTION enqueue_package_commerce_outbox_delivery();

CREATE FUNCTION protect_package_commerce_outbox_attempt()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'TRUNCATE' THEN
        RAISE EXCEPTION 'package commerce outbox attempts cannot be truncated';
    ELSIF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'package commerce outbox attempts cannot be deleted';
    ELSIF TG_OP = 'INSERT' THEN
        IF NEW.result <> 'leased' OR NEW.result_code IS NOT NULL
           OR NEW.next_attempt_at IS NOT NULL OR NEW.completed_at IS NOT NULL THEN
            RAISE EXCEPTION 'package commerce outbox attempt must start leased';
        END IF;
        RETURN NEW;
    END IF;
	IF OLD.result <> 'leased'
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.outbox_id IS DISTINCT FROM OLD.outbox_id
       OR NEW.attempt_no IS DISTINCT FROM OLD.attempt_no
       OR NEW.lease_owner IS DISTINCT FROM OLD.lease_owner
       OR NEW.lease_token IS DISTINCT FROM OLD.lease_token
       OR NEW.lease_fence IS DISTINCT FROM OLD.lease_fence
       OR NEW.leased_at IS DISTINCT FROM OLD.leased_at
       OR NEW.lease_expires_at IS DISTINCT FROM OLD.lease_expires_at
	       OR NEW.result = 'leased' THEN
	        RAISE EXCEPTION 'package commerce outbox attempt is immutable after completion';
	    END IF;
	    IF NOT EXISTS (
	        SELECT 1 FROM package_commerce_outbox_deliveries delivery
	        WHERE delivery.outbox_id = OLD.outbox_id
	          AND delivery.state = 'leased'
	          AND delivery.lease_owner = OLD.lease_owner
	          AND delivery.lease_token = OLD.lease_token
	          AND delivery.lease_fence = OLD.lease_fence
	    ) THEN
	        RAISE EXCEPTION 'package commerce outbox attempt lease no longer owns delivery';
	    END IF;
	    RETURN NEW;
END;
$$;

CREATE TRIGGER package_commerce_outbox_attempts_protect
BEFORE INSERT OR UPDATE OR DELETE ON package_commerce_outbox_attempts
FOR EACH ROW EXECUTE FUNCTION protect_package_commerce_outbox_attempt();
CREATE TRIGGER package_commerce_outbox_attempts_no_truncate
BEFORE TRUNCATE ON package_commerce_outbox_attempts
FOR EACH STATEMENT EXECUTE FUNCTION protect_package_commerce_outbox_attempt();

CREATE FUNCTION validate_package_balance_hold_settlement()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE hold_order_id uuid;
DECLARE hold_tenant_id uuid;
DECLARE hold_currency text;
DECLARE hold_amount bigint;
DECLARE hold_event_revision bigint;
DECLARE hold_event_type text;
DECLARE order_event_revision bigint;
DECLARE transaction_tenant uuid;
DECLARE transaction_currency text;
DECLARE transaction_amount bigint;
DECLARE transaction_order uuid;
DECLARE transaction_hold uuid;
DECLARE transaction_direction text;
DECLARE transaction_operation text;
DECLARE order_operation text;
BEGIN
    SELECT order_id, tenant_scope_id, currency, amount_minor
    INTO hold_order_id, hold_tenant_id, hold_currency, hold_amount
    FROM package_balance_holds WHERE id = NEW.hold_id FOR UPDATE;
    IF hold_order_id IS NULL OR hold_order_id IS DISTINCT FROM NEW.order_id THEN
        RAISE EXCEPTION 'package balance hold settlement does not match hold order';
    END IF;
    SELECT revision, event_type INTO hold_event_revision, hold_event_type
    FROM package_balance_hold_events WHERE hold_id = NEW.hold_id
    ORDER BY revision DESC LIMIT 1;
	    SELECT revision INTO order_event_revision
	    FROM package_order_events WHERE order_id = NEW.order_id
	    ORDER BY revision DESC LIMIT 1;
	    SELECT operation INTO order_operation FROM package_orders WHERE id = NEW.order_id;
    IF hold_event_revision IS DISTINCT FROM NEW.hold_revision
       OR hold_event_type IS DISTINCT FROM NEW.outcome
       OR order_event_revision IS DISTINCT FROM NEW.order_revision THEN
        RAISE EXCEPTION 'package balance hold settlement does not match append-only heads';
    END IF;
    IF NEW.outcome = 'captured' THEN
	        SELECT target_scope_id, currency, amount_minor, commercial_order_id,
	               balance_hold_id, direction, operation
	        INTO transaction_tenant, transaction_currency, transaction_amount,
	             transaction_order, transaction_hold, transaction_direction,
	             transaction_operation
	        FROM billing_transactions WHERE id = NEW.billing_transaction_id;
        IF transaction_tenant IS DISTINCT FROM hold_tenant_id
           OR transaction_currency IS DISTINCT FROM hold_currency
           OR transaction_amount IS DISTINCT FROM hold_amount
           OR transaction_order IS DISTINCT FROM hold_order_id
           OR transaction_hold IS DISTINCT FROM NEW.hold_id
	           OR transaction_direction IS DISTINCT FROM 'debit'
	           OR transaction_operation IS DISTINCT FROM (CASE order_operation
	               WHEN 'upgrade' THEN 'package_upgrade'
	               WHEN 'downgrade' THEN 'package_downgrade'
	               ELSE NULL
	           END) THEN
            RAISE EXCEPTION 'package balance hold capture transaction does not match hold';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION assert_package_balance_hold_transaction()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.balance_hold_id IS NULL THEN
        RETURN NULL;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM package_balance_hold_settlements settlement
        WHERE settlement.hold_id = NEW.balance_hold_id
          AND settlement.outcome = 'captured'
          AND settlement.billing_transaction_id = NEW.id
    ) THEN
        RAISE EXCEPTION 'package balance hold transaction requires captured settlement';
    END IF;
    RETURN NULL;
END;
$$;

CREATE TRIGGER package_balance_hold_settlements_validate
BEFORE INSERT ON package_balance_hold_settlements
FOR EACH ROW EXECUTE FUNCTION validate_package_balance_hold_settlement();
CREATE TRIGGER package_balance_hold_settlements_append_only
BEFORE UPDATE OR DELETE ON package_balance_hold_settlements
FOR EACH ROW EXECUTE FUNCTION prevent_package_commerce_fact_mutation();
CREATE TRIGGER package_balance_hold_settlements_no_truncate
BEFORE TRUNCATE ON package_balance_hold_settlements
FOR EACH STATEMENT EXECUTE FUNCTION prevent_package_commerce_fact_mutation();
CREATE CONSTRAINT TRIGGER billing_transactions_balance_hold_valid
AFTER INSERT ON billing_transactions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION assert_package_balance_hold_transaction();
