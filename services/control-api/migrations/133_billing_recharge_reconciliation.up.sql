LOCK TABLE schema_migrations,permissions,roles,role_permissions,billing_accounts,
    billing_transactions,billing_postings,audit_events,auth_sessions
IN ACCESS EXCLUSIVE MODE;

DO $migration_133$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 132 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 132 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state IS DISTINCT FROM 'verified'
           OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=132 AND migration_id='132_analytics_log_export'
          AND checksum_sha256='3afde20714a6fab00099c7506173138767a303c2119c6eeeba3826c3f2087719'
          AND down_checksum_sha256='f6a3dfaad783f62cbfd7c61f1b59f7705c6872aee78be1d37e7bec9897bbc279'
          AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR to_regclass('recharge_orders_v1') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 133 requires the exact verified 132 release head' USING ERRCODE='P1330';
    END IF;
END;
$migration_133$;

INSERT INTO permissions(name,description) VALUES
    ('billing.recharges.create','Create a tenant recharge order'),
    ('billing.recharges.read','Read reconciled recharge orders and statistics'),
    ('billing.recharges.manage','Operate billing recharge reconciliation');

INSERT INTO role_permissions(role_id,permission_name)
SELECT role.id,'billing.recharges.create'
FROM roles role JOIN access_scopes scope ON scope.id=role.scope_id AND scope.kind='tenant'
WHERE role.system_role AND role.name='tenant_owner'
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions(role_id,permission_name)
SELECT role.id,permission.name
FROM roles role
CROSS JOIN (VALUES('billing.recharges.read'),('billing.recharges.manage')) permission(name)
JOIN access_scopes scope ON scope.id=role.scope_id AND scope.kind='platform'
WHERE role.system_role AND role.name='platform_owner'
ON CONFLICT DO NOTHING;

CREATE TABLE recharge_orders_v1 (
    id uuid PRIMARY KEY CHECK(id<>'00000000-0000-0000-0000-000000000000'::uuid),
    tenant_scope_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    channel text NOT NULL CHECK(channel IN ('alipay','wechat','transfer')),
    provider text CHECK(provider IS NULL OR provider ~ '^[a-z][a-z0-9._-]{0,63}$'),
    provider_account_id text CHECK(provider_account_id IS NULL OR provider_account_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    external_payment_id text CHECK(external_payment_id IS NULL OR external_payment_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    amount_minor bigint NOT NULL CHECK(amount_minor BETWEEN 1 AND 9000000000000000),
    currency text NOT NULL CHECK(currency='CNY'),
    state text NOT NULL CHECK(state IN ('pending','paid','failed','canceled')),
    revision bigint NOT NULL CHECK(revision>0),
    created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
    updated_at timestamptz NOT NULL CHECK(isfinite(updated_at) AND updated_at>=created_at),
    FOREIGN KEY(tenant_scope_id,tenant_id) REFERENCES access_scopes(id,tenant_id) ON DELETE RESTRICT,
    FOREIGN KEY(tenant_scope_id,user_id) REFERENCES memberships(scope_id,user_id) ON DELETE RESTRICT,
    UNIQUE(provider,provider_account_id,external_payment_id),
    CONSTRAINT recharge_orders_callback_identity_133
        UNIQUE(id,tenant_scope_id,amount_minor,currency),
    UNIQUE(id,tenant_scope_id,tenant_id,user_id,amount_minor,currency),
    CHECK((provider IS NULL AND provider_account_id IS NULL AND external_payment_id IS NULL) OR
          (provider IS NOT NULL AND provider_account_id IS NOT NULL AND external_payment_id IS NOT NULL)),
    CHECK((state='pending' AND revision=1) OR (state<>'pending' AND revision=2))
);

CREATE INDEX recharge_orders_scope_created_v1_idx
    ON recharge_orders_v1(tenant_scope_id,created_at DESC,id DESC);
CREATE INDEX recharge_orders_admin_created_v1_idx
    ON recharge_orders_v1(created_at DESC,id DESC);
CREATE INDEX recharge_orders_user_created_v1_idx
    ON recharge_orders_v1(user_id,created_at DESC,id DESC);
CREATE INDEX recharge_orders_channel_created_v1_idx
    ON recharge_orders_v1(channel,created_at DESC,id DESC);
CREATE INDEX recharge_orders_state_created_v1_idx
    ON recharge_orders_v1(state,created_at DESC,id DESC);

CREATE TABLE recharge_order_events_v1 (
    id uuid PRIMARY KEY,
    order_id uuid NOT NULL REFERENCES recharge_orders_v1(id) ON DELETE RESTRICT,
    revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 2),
    state text NOT NULL CHECK(state IN ('pending','paid','failed','canceled')),
    reason_code text NOT NULL CHECK(reason_code ~ '^[a-z][a-z0-9._-]{0,95}$'),
    occurred_at timestamptz NOT NULL CHECK(isfinite(occurred_at)),
    UNIQUE(order_id,revision)
);

CREATE TABLE recharge_provider_callbacks_v1 (
    id uuid PRIMARY KEY,
    order_id uuid NOT NULL,
    tenant_scope_id uuid NOT NULL,
    provider text NOT NULL CHECK(provider ~ '^[a-z][a-z0-9._-]{0,63}$'),
    provider_account_id text NOT NULL CHECK(provider_account_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    external_event_id text NOT NULL CHECK(external_event_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    external_payment_id text NOT NULL CHECK(external_payment_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    state text NOT NULL CHECK(state IN ('paid','failed')),
    amount_minor bigint NOT NULL CHECK(amount_minor BETWEEN 1 AND 9000000000000000),
    currency text NOT NULL CHECK(currency='CNY'),
    payload_sha256 bytea NOT NULL CHECK(octet_length(payload_sha256)=32),
    signature_sha256 bytea NOT NULL CHECK(octet_length(signature_sha256)=32),
    verification_key_id text NOT NULL CHECK(verification_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    occurred_at timestamptz NOT NULL CHECK(isfinite(occurred_at)),
    received_at timestamptz NOT NULL CHECK(isfinite(received_at) AND received_at>=occurred_at),
    processing_result text NOT NULL CHECK(processing_result IN ('applied','ignored_terminal')),
    FOREIGN KEY(order_id,tenant_scope_id,amount_minor,currency)
        REFERENCES recharge_orders_v1(id,tenant_scope_id,amount_minor,currency) ON DELETE RESTRICT,
    UNIQUE(provider,provider_account_id,external_event_id),
    UNIQUE(id,order_id,tenant_scope_id,amount_minor,currency)
);

CREATE INDEX recharge_callbacks_order_identity_v1_idx
    ON recharge_provider_callbacks_v1(order_id,tenant_scope_id,amount_minor,currency);

ALTER TABLE billing_transactions DROP CONSTRAINT billing_transactions_commerce_shape;
ALTER TABLE billing_transactions DROP CONSTRAINT billing_transactions_operation_check;
ALTER TABLE billing_transactions
    ADD COLUMN recharge_order_id uuid REFERENCES recharge_orders_v1(id) ON DELETE RESTRICT,
    ADD CONSTRAINT billing_transactions_operation_check CHECK(operation IN (
        'manual_adjustment','provider_payment','package_purchase','package_renewal',
        'package_upgrade','package_downgrade','package_refund','package_void',
        'traffic_package_purchase','recharge_payment'
    )),
    ADD CONSTRAINT billing_transactions_commerce_shape CHECK(
        (operation='manual_adjustment' AND commercial_order_id IS NULL AND reverses_transaction_id IS NULL
            AND payment_attempt_id IS NULL AND recharge_order_id IS NULL)
        OR (operation='provider_payment' AND commercial_order_id IS NOT NULL AND reverses_transaction_id IS NULL
            AND payment_attempt_id IS NOT NULL AND recharge_order_id IS NULL AND direction='credit')
        OR (operation IN ('package_purchase','package_renewal','package_upgrade','package_downgrade','traffic_package_purchase')
            AND commercial_order_id IS NOT NULL AND reverses_transaction_id IS NULL AND recharge_order_id IS NULL)
        OR (operation IN ('package_refund','package_void') AND commercial_order_id IS NOT NULL
            AND reverses_transaction_id IS NOT NULL AND recharge_order_id IS NULL AND direction='credit')
        OR (operation='recharge_payment' AND commercial_order_id IS NULL AND reverses_transaction_id IS NULL
            AND payment_attempt_id IS NULL AND recharge_order_id IS NOT NULL AND direction='credit')
    ),
    ADD CONSTRAINT billing_transactions_recharge_identity_133
        UNIQUE(id,recharge_order_id,target_scope_id,amount_minor,currency);

CREATE UNIQUE INDEX billing_transactions_recharge_order_v1_idx
    ON billing_transactions(recharge_order_id) WHERE recharge_order_id IS NOT NULL;

CREATE TABLE recharge_settlements_v1 (
    id uuid PRIMARY KEY,
    order_id uuid NOT NULL,
    callback_id uuid NOT NULL,
    transaction_id uuid NOT NULL,
    tenant_scope_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    amount_minor bigint NOT NULL,
    currency text NOT NULL,
    settled_at timestamptz NOT NULL CHECK(isfinite(settled_at)),
    FOREIGN KEY(order_id,tenant_scope_id,tenant_id,user_id,amount_minor,currency)
        REFERENCES recharge_orders_v1(id,tenant_scope_id,tenant_id,user_id,amount_minor,currency) ON DELETE RESTRICT,
    FOREIGN KEY(callback_id,order_id,tenant_scope_id,amount_minor,currency)
        REFERENCES recharge_provider_callbacks_v1(id,order_id,tenant_scope_id,amount_minor,currency) ON DELETE RESTRICT,
    FOREIGN KEY(transaction_id,order_id,tenant_scope_id,amount_minor,currency)
        REFERENCES billing_transactions(id,recharge_order_id,target_scope_id,amount_minor,currency) ON DELETE RESTRICT,
    UNIQUE(order_id),UNIQUE(callback_id),UNIQUE(transaction_id),
    UNIQUE(id,order_id,callback_id,transaction_id,tenant_scope_id,tenant_id,user_id,amount_minor,currency,settled_at)
);

CREATE TABLE recharge_statistics_facts_v1 (
    id uuid PRIMARY KEY,
    settlement_id uuid NOT NULL,
    order_id uuid NOT NULL,
    callback_id uuid NOT NULL,
    transaction_id uuid NOT NULL,
    tenant_scope_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    channel text NOT NULL CHECK(channel IN ('alipay','wechat','transfer')),
    amount_minor bigint NOT NULL,
    currency text NOT NULL,
    settled_at timestamptz NOT NULL CHECK(isfinite(settled_at)),
    FOREIGN KEY(settlement_id,order_id,callback_id,transaction_id,tenant_scope_id,tenant_id,user_id,amount_minor,currency,settled_at)
        REFERENCES recharge_settlements_v1(id,order_id,callback_id,transaction_id,tenant_scope_id,tenant_id,user_id,amount_minor,currency,settled_at)
        ON DELETE RESTRICT,
    UNIQUE(settlement_id),UNIQUE(order_id),UNIQUE(callback_id),UNIQUE(transaction_id)
);

CREATE INDEX recharge_statistics_time_v1_idx
    ON recharge_statistics_facts_v1(settled_at DESC,id DESC);
CREATE INDEX recharge_statistics_tenant_time_v1_idx
    ON recharge_statistics_facts_v1(tenant_scope_id,settled_at DESC,id DESC);
CREATE INDEX recharge_statistics_user_time_v1_idx
    ON recharge_statistics_facts_v1(user_id,settled_at DESC,id DESC);
CREATE INDEX recharge_statistics_channel_time_v1_idx
    ON recharge_statistics_facts_v1(channel,settled_at DESC,id DESC);

ALTER TABLE auth_sessions
    ADD CONSTRAINT auth_sessions_recharge_receipt_identity_133 UNIQUE(id,scope_id,user_id);

CREATE TABLE recharge_write_receipts_v1 (
    id uuid PRIMARY KEY,
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    actor_session_id uuid NOT NULL,
    operation text NOT NULL CHECK(operation='billing.recharge.order.create'),
    idempotency_key text NOT NULL CHECK(idempotency_key ~ '^[A-Za-z0-9._-]{1,128}$'),
    request_id text NOT NULL CHECK(request_id ~ '^[A-Za-z0-9._-]{1,128}$'),
    request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),
    order_id uuid NOT NULL REFERENCES recharge_orders_v1(id) ON DELETE RESTRICT,
    response_body jsonb NOT NULL CHECK(jsonb_typeof(response_body)='object' AND octet_length(response_body::text)<=16384),
    created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
    FOREIGN KEY(actor_scope_id,actor_user_id) REFERENCES memberships(scope_id,user_id) ON DELETE RESTRICT,
    FOREIGN KEY(actor_session_id,actor_scope_id,actor_user_id) REFERENCES auth_sessions(id,scope_id,user_id) ON DELETE RESTRICT,
    UNIQUE(actor_scope_id,actor_user_id,actor_session_id,idempotency_key),
    UNIQUE(actor_scope_id,actor_user_id,actor_session_id,request_id)
);

CREATE INDEX recharge_receipts_session_identity_v1_idx
    ON recharge_write_receipts_v1(actor_session_id,actor_scope_id,actor_user_id);
CREATE INDEX recharge_receipts_order_v1_idx ON recharge_write_receipts_v1(order_id);

CREATE FUNCTION guard_billing_recharge_order_head_133()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' THEN
        RAISE EXCEPTION 'recharge order head is append-only' USING ERRCODE='P1331';
    END IF;
    IF OLD.id<>NEW.id OR OLD.tenant_scope_id<>NEW.tenant_scope_id OR OLD.tenant_id<>NEW.tenant_id OR
       OLD.user_id<>NEW.user_id OR OLD.channel<>NEW.channel OR OLD.amount_minor<>NEW.amount_minor OR
       OLD.currency<>NEW.currency OR OLD.created_at<>NEW.created_at OR OLD.state<>'pending' OR
       NEW.state NOT IN ('paid','failed','canceled') OR NEW.revision<>OLD.revision+1 OR
       NEW.updated_at<OLD.updated_at THEN
        RAISE EXCEPTION 'recharge order head transition is invalid' USING ERRCODE='P1331';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION prevent_billing_recharge_fact_mutation_133()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% is append-only',TG_TABLE_NAME USING ERRCODE='P1332';
END;
$$;

CREATE FUNCTION validate_billing_recharge_reconciliation_133()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    matches bigint;
    target_settlement_id uuid;
BEGIN
    IF TG_TABLE_NAME='recharge_settlements_v1' THEN
        target_settlement_id := NEW.id;
    ELSE
        target_settlement_id := NEW.settlement_id;
    END IF;
    SELECT count(*) INTO matches
    FROM recharge_settlements_v1 settlement
    JOIN recharge_orders_v1 recharge_order ON recharge_order.id=settlement.order_id AND recharge_order.state='paid'
    JOIN recharge_provider_callbacks_v1 callback ON callback.id=settlement.callback_id AND callback.state='paid'
    JOIN billing_transactions transaction ON transaction.id=settlement.transaction_id
        AND transaction.operation='recharge_payment' AND transaction.direction='credit'
    JOIN recharge_statistics_facts_v1 statistic ON statistic.settlement_id=settlement.id
    WHERE settlement.id=target_settlement_id
      AND recharge_order.tenant_scope_id=settlement.tenant_scope_id
      AND callback.tenant_scope_id=settlement.tenant_scope_id
      AND transaction.target_scope_id=settlement.tenant_scope_id
      AND statistic.tenant_scope_id=settlement.tenant_scope_id
      AND recharge_order.amount_minor=settlement.amount_minor
      AND callback.amount_minor=settlement.amount_minor
      AND transaction.amount_minor=settlement.amount_minor
      AND statistic.amount_minor=settlement.amount_minor;
    IF matches<>1 THEN
        RAISE EXCEPTION 'billing recharge four-way reconciliation failed' USING ERRCODE='P1333';
    END IF;
    RETURN NULL;
END;
$$;

CREATE TRIGGER recharge_orders_head_guard_v1
BEFORE UPDATE OR DELETE ON recharge_orders_v1
FOR EACH ROW EXECUTE FUNCTION guard_billing_recharge_order_head_133();

CREATE TRIGGER recharge_order_events_append_only_v1 BEFORE UPDATE OR DELETE ON recharge_order_events_v1
FOR EACH ROW EXECUTE FUNCTION prevent_billing_recharge_fact_mutation_133();
CREATE TRIGGER recharge_callbacks_append_only_v1 BEFORE UPDATE OR DELETE ON recharge_provider_callbacks_v1
FOR EACH ROW EXECUTE FUNCTION prevent_billing_recharge_fact_mutation_133();
CREATE TRIGGER recharge_settlements_append_only_v1 BEFORE UPDATE OR DELETE ON recharge_settlements_v1
FOR EACH ROW EXECUTE FUNCTION prevent_billing_recharge_fact_mutation_133();
CREATE TRIGGER recharge_statistics_append_only_v1 BEFORE UPDATE OR DELETE ON recharge_statistics_facts_v1
FOR EACH ROW EXECUTE FUNCTION prevent_billing_recharge_fact_mutation_133();
CREATE TRIGGER recharge_receipts_append_only_v1 BEFORE UPDATE OR DELETE ON recharge_write_receipts_v1
FOR EACH ROW EXECUTE FUNCTION prevent_billing_recharge_fact_mutation_133();

CREATE CONSTRAINT TRIGGER recharge_settlements_reconciled_v1
AFTER INSERT ON recharge_settlements_v1 DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_billing_recharge_reconciliation_133();
CREATE CONSTRAINT TRIGGER recharge_statistics_reconciled_v1
AFTER INSERT ON recharge_statistics_facts_v1 DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_billing_recharge_reconciliation_133();
